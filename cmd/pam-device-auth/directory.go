package main

import (
	"bufio"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/cache"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/device"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/qr"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/sshclient"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/token"
)

// timed runs fn and logs at DEBUG how long step took: with --debug a slow
// login shows which request to the identity provider was slow.
func timed(log *logger.Logger, step string, fn func()) {
	start := time.Now()
	fn()
	log.Debug("%s took %s", step, time.Since(start).Round(time.Millisecond))
}

// outcome is the result of a login attempt. The zero value denies, so a path
// that never sets it cannot let a login through.
type outcome int

const (
	denySoft outcome = iota // failed; sshd may let the user try again
	denyHard                // denied (missing role, no directory identity); no retry
	allow
)

// exitCode is the helper's exit status for an outcome, as pam_device_auth.c
// reads it: 0 success, 2 hard deny, everything else a soft failure.
func (o outcome) exitCode() int {
	switch o {
	case allow:
		return 0
	case denyHard:
		return 2
	default:
		return 1
	}
}

// authIO is the helper's side of the line protocol with the PAM module: the
// module collects info lines and shows them with the next "FLUSH:" line, which
// is a prompt that the module answers with one line.
type authIO struct {
	in  *bufio.Reader
	out io.Writer
}

// info writes one info line.
func (a *authIO) info(format string, args ...any) {
	fmt.Fprintf(a.out, format+"\n", args...)
}

// prompt shows text as a prompt and waits for the answer line. The error says
// that no complete line arrived (the other side is gone).
func (a *authIO) prompt(text string) error {
	fmt.Fprintf(a.out, "FLUSH:%s\n", text)
	_, err := a.in.ReadString('\n')
	return err
}

// authFlow is one login attempt on a host where identity comes from the
// directory (via SSSD/NSS). pam-device-auth here is ONLY the extra OIDC
// SSH-login layer: it validates an OIDC token (signature/issuer/client/exp/iat,
// required_role, optional required_acr) for the SSH user, then grants or
// denies the login. It NEVER reads /etc/shadow, never prompts for a local
// password, and never creates users or manages groups — SSSD and the directory
// own identity, groups, home dir, and the sudo password (pam_sss).
type authFlow struct {
	log       *logger.Logger
	cfg       *config.Config
	client    *http.Client
	endpoints *discovery.Endpoints
	io        *authIO
	// nss reports whether a user resolves through SSSD (nssLookup).
	nss func(user string) (found bool, err error)
}

// run decides the login of sshUser from clientIP: the directory identity gate,
// then the cached session of a known address, then the device flow.
func (f *authFlow) run(sshUser, clientIP string) outcome {
	// The login name becomes an argument of getent; a name that looks like an
	// option is no directory user and never reaches a command line.
	if err := loginNameError(sshUser); err != nil {
		f.log.Error("Directory: refusing login name %q: %v; denying", sshUser, err)
		f.deny("Access denied: no directory identity for this user.")
		return denyHard
	}

	// Defensive NSS identity gate. In directory mode the SSH user MUST resolve
	// via NSS (SSSD/LDAP). The deployed sshd config already guarantees this —
	// publickey is served from the directory by sss_ssh_authorizedkeys, so an
	// unknown user never reaches PAM — but if the module is wired without that
	// drop-in we must not grant access (or cache a refresh token) for a user
	// who has no Unix identity. getent -s sss queries SSSD only — local
	// /etc/passwd accounts must not pass the directory gate.
	found, nssErr := f.nss(sshUser)
	if ok, logMsg, banner := identityGate(sshUser, found, nssErr); !ok {
		f.log.Error("%s", logMsg)
		f.deny(banner)
		return denyHard
	}

	if o, done := f.cached(sshUser, clientIP); done {
		return o
	}
	return f.device(sshUser, clientIP)
}

// cached uses a cached refresh token for a known IP to re-validate with the
// IdP without a browser round-trip. done reports whether that settled the
// login: allow, or a hard deny for a genuine access denial on a known IP (role
// revoked) — no point re-prompting. A soft failure (network, expired refresh)
// leaves done false: device flow required.
func (f *authFlow) cached(sshUser, clientIP string) (o outcome, done bool) {
	log, cfg, httpClient, endpoints := f.log, f.cfg, f.client, f.endpoints
	denyReason := ""
	err := cache.WithUserLock(sshUser, func() error {
		session, err := cache.Load(sshUser)
		if errors.Is(err, cache.ErrCorrupt) {
			log.Warn("Directory: session cache for %s is corrupt (%v); removing it, device auth", sshUser, err)
			return cache.Delete(sshUser)
		}
		if err != nil || session == nil {
			return err
		}
		if clientIP == "unknown" || !session.HasIP(clientIP) {
			return nil
		}

		// Keep the per-user lock for the complete refresh-token rotation. Without
		// this, two PAM processes can submit the same one-time refresh token and
		// the loser can delete or overwrite the winner's newly rotated token.
		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		var tokenResp *device.TokenResponse
		timed(log, "Token refresh", func() {
			tokenResp, err = device.RefreshToken(ctx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, session.RefreshToken)
		})
		cancel()
		if err != nil {
			if errors.Is(err, device.ErrRefreshRejected) {
				log.Warn("Directory: token refresh rejected by the IdP (cache cleared, device auth): %v", err)
				return cache.Delete(sshUser)
			}
			// Network error or IdP outage: the refresh token may still be good,
			// so keep the cached session; device flow required for this login.
			log.Warn("Directory: token refresh failed, keeping cached session (device auth): %v", err)
			return nil
		}

		result, err := validateDirectoryToken(log, httpClient, endpoints, cfg, tokenResp.AccessToken, sshUser)
		if err != nil {
			log.Warn("Directory: validation failed after refresh (cache cleared, device auth): %v", err)
			return cache.Delete(sshUser)
		}

		if reason := roleDenial(result, cfg); reason != "" {
			log.Error("Directory: access revoked for %s on known IP %s: %s", sshUser, clientIP, reason)
			_ = cache.Delete(sshUser)
			// The banner waits for the user; it is shown after the lock is released.
			denyReason = reason
			o, done = denyHard, true
			return nil
		}
		// The authentication level of a refreshed token is what the session
		// had, or what the provider still vouches for; a new device login can
		// reach the required level. So this is no revocation: device flow.
		if reason := acrDenial(result, cfg); reason != "" {
			log.Warn("Directory: refreshed token of %s does not meet required_acr (cache cleared, device auth): %s", sshUser, reason)
			return cache.Delete(sshUser)
		}

		log.Info("Directory auth OK (cached): user=%s roles=%v", result.Username, result.Roles)
		if tokenResp.RefreshToken != "" {
			session.RefreshToken = tokenResp.RefreshToken
			if err := cache.Save(session); err != nil {
				return err
			}
		}
		o, done = allow, true
		return nil
	})
	if err != nil {
		log.Warn("Directory: session cache error: %v", err)
	}
	if denyReason != "" {
		f.deny(denyReason)
	}
	return o, done
}

// device runs the full device-grant flow and grants or denies login.
func (f *authFlow) device(sshUser, clientIP string) outcome {
	log, cfg, httpClient, endpoints := f.log, f.cfg, f.client, f.endpoints
	reqCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	var (
		dc  *device.DeviceCode
		err error
	)
	timed(log, "Device code request", func() {
		dc, err = device.RequestCode(reqCtx, httpClient, endpoints.DeviceAuthorizationEndpoint, cfg.ClientID)
	})
	cancel()
	if err != nil {
		log.Error("Device code request failed: %v", err)
		f.io.info("Authentication failed.")
		return denySoft
	}

	// These IdP-supplied values reach the SSH client's terminal via the PAM
	// conversation — scrub them before any display (including the QR payload).
	dc.VerificationURI = sanitizeDisplay(dc.VerificationURI)
	dc.VerificationURIComplete = sanitizeDisplay(dc.VerificationURIComplete)
	dc.UserCode = sanitizeDisplay(dc.UserCode)

	f.io.info("------------------------------------")
	if dc.VerificationURIComplete != "" {
		f.io.info("Link:  %s", dc.VerificationURIComplete)
		f.io.info("Code:  %s", dc.UserCode)
		show, client, reason := sshclient.QRDecision(cfg.ShowQR)
		log.Info("%s", qrDecisionMessage(show, client, reason))
		if show && canRenderQR(dc.VerificationURIComplete) {
			f.io.info("")
			if qrStr, err := qr.Render(dc.VerificationURIComplete); err == nil {
				fmt.Fprint(f.io.out, qrStr)
			}
		} else if show {
			log.Info("%s", qrNotRenderedMessage(dc.VerificationURIComplete))
		}
	} else {
		f.io.info("Open:  %s", dc.VerificationURI)
		f.io.info("Code:  %s", dc.UserCode)
	}
	f.io.info("------------------------------------")
	if err := f.io.prompt("Authorize in browser, then press Enter... "); err != nil {
		// No answer line means the PAM side is gone: the SSH client disconnected
		// and sshd ended its PAM process. Polling on would complete a login that
		// nobody waits for and store its session.
		log.Warn("Device flow: the SSH client went away at the prompt (%v); aborting", err)
		return denySoft
	}

	timeout := cfg.AuthTimeout
	if dc.ExpiresIn > 0 && dc.ExpiresIn < timeout {
		timeout = dc.ExpiresIn
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	log.Info("Directory: waiting for authorization (timeout: %ds)", timeout)
	tokenResp, err := device.PollToken(ctx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, dc.DeviceCode, dc.Interval)
	if err != nil {
		log.Error("Token polling failed: %v", err)
		f.io.info("Authentication failed.")
		return denySoft
	}

	result, err := validateDirectoryToken(log, httpClient, endpoints, cfg, tokenResp.AccessToken, sshUser)
	if err != nil {
		log.Error("Token validation failed: %v", err)
		f.io.info("Authentication failed.")
		return denySoft
	}

	if reason := checkDirectoryAccess(result, cfg); reason != "" {
		log.Error("Directory: access denied for %s: %s", sshUser, reason)
		f.deny(reason)
		return denyHard
	}

	log.Info("Directory auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	rememberDeviceLogin(log, sshUser, tokenResp.RefreshToken, clientIP)
	return allow
}

// qrDecisionMessage is the device flow's log line for the QR decision: the
// detected SSH client (already scrubbed by sshclient, quoted here) and whether
// the QR is shown, with the reason ("client" or "configured").
func qrDecisionMessage(show bool, client, reason string) string {
	state := "hidden"
	if show {
		state = "shown"
	}
	return fmt.Sprintf("Directory: SSH client %q, QR %s (%s)", client, state, reason)
}

// qrNotRenderedMessage is the second log line when the client would render the
// QR but the verification URL is longer than qrMaxURLBytes (canRenderQR).
func qrNotRenderedMessage(url string) string {
	return fmt.Sprintf("Directory: QR not rendered, verification URL is %d bytes (limit %d)", len(url), qrMaxURLBytes)
}

// rememberDeviceLogin stores the refresh token and the client IP for the
// cached login (tryCachedDirectory). Without a refresh token from the IdP there
// is nothing to cache, and a session from an earlier login is removed: the
// cached login must reflect the latest device login, for example after the IdP
// stopped issuing refresh tokens for the client.
func rememberDeviceLogin(log *logger.Logger, sshUser, refreshToken, clientIP string) {
	if refreshToken == "" {
		log.Debug("Directory: the IdP returned no refresh token, no cached login for %s", sshUser)
		if err := cache.WithUserLock(sshUser, func() error { return cache.Delete(sshUser) }); err != nil {
			log.Warn("Directory: could not remove the earlier cached session of %s: %v", sshUser, err)
		}
		return
	}
	if err := cache.Update(sshUser, func(s *cache.CachedSession) {
		s.RefreshToken = refreshToken
		s.AddIP(clientIP)
	}); err != nil {
		log.Warn("Directory: session cache save failed (non-fatal, next login needs the device flow again): %v", err)
	}
}

// validateDirectoryToken loads the JWKS (root-only metadata cache, live on a
// miss), validates the token (signature, issuer, client binding, exp/iat,
// allowed algorithms), and confirms the token subject matches the SSH user.
// Policy (role, acr) is checked separately by checkDirectoryAccess so callers
// can distinguish "bad token" from "denied".
func validateDirectoryToken(log *logger.Logger, httpClient *http.Client, endpoints *discovery.Endpoints, cfg *config.Config, accessToken, sshUser string) (*token.TokenResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	var (
		keys   map[string]crypto.PublicKey
		cached bool
		err    error
	)
	timed(log, "JWKS fetch", func() {
		keys, cached, err = token.FetchJWKSCached(ctx, httpClient, endpoints.JwksURI, cfg.IssuerURL, log.Debug, log.Warn)
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch: %w", err)
	}

	result, err := token.Validate(accessToken, keys, endpoints.Issuer, cfg.ClientID, cfg.RoleClaim, cfg.AllowedAlgorithms)
	if cached && errors.Is(err, token.ErrUnknownKeyID) {
		// The IdP may have rotated its signing key since the JWKS was cached.
		// Refetch live exactly once (overwriting the cache) and retry. Every
		// other validation error, including a bad signature under a known
		// kid, is final and must not trigger network traffic.
		log.Debug("JWKS cache has no key for token kid, refetching live")
		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		keys, err = token.RefreshJWKS(ctx, httpClient, endpoints.JwksURI, cfg.IssuerURL, log.Warn)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("JWKS fetch: %w", err)
		}
		result, err = token.Validate(accessToken, keys, endpoints.Issuer, cfg.ClientID, cfg.RoleClaim, cfg.AllowedAlgorithms)
	}
	if err != nil {
		return nil, err
	}
	if result.Username != sshUser {
		return nil, fmt.Errorf("username mismatch: token=%q ssh=%q", result.Username, sshUser)
	}
	return result, nil
}

// checkDirectoryAccess applies the token policy: the required role, then the
// accepted authentication levels (required_acr, exact match). It returns the
// deny reason or "". The `clients` IP allowlist is enforced separately in the
// PAM account phase (acct.go) for every login, so it is not re-checked here.
func checkDirectoryAccess(result *token.TokenResult, cfg *config.Config) string {
	if reason := roleDenial(result, cfg); reason != "" {
		return reason
	}
	return acrDenial(result, cfg)
}

// roleDenial is the deny reason for a token without the required role, or "".
func roleDenial(result *token.TokenResult, cfg *config.Config) string {
	if !token.HasRole(result.Roles, cfg.RequiredRole) {
		return fmt.Sprintf("Access denied: '%s' lacks required role '%s'.", result.Username, cfg.RequiredRole)
	}
	return ""
}

// acrDenial is the deny reason for a token whose authentication level (acr)
// is missing or not in required_acr, or "". Without required_acr every token
// passes.
func acrDenial(result *token.TokenResult, cfg *config.Config) string {
	if len(cfg.RequiredACR) > 0 && !slices.Contains(cfg.RequiredACR, result.ACR) {
		if result.ACR == "" {
			return "Access denied: the token carries no authentication level (acr); the identity provider must add the acr claim (Keycloak: client scope acr)."
		}
		return fmt.Sprintf("Access denied: authentication level %q is not accepted (required: %s).", result.ACR, strings.Join(cfg.RequiredACR, ", "))
	}
	return ""
}

// identityGate maps the outcome of the SSSD lookup to the login decision. Both
// denials end the login, but the log line must tell an SSSD outage apart from
// a user that has no directory identity.
func identityGate(user string, found bool, lookupErr error) (allow bool, logMsg, banner string) {
	switch {
	case lookupErr != nil:
		return false,
			fmt.Sprintf("Directory: NSS lookup for %s failed (SSSD unavailable?): %v; denying", user, lookupErr),
			"Access denied: directory lookup failed. Try again later or contact your administrator."
	case !found:
		return false,
			fmt.Sprintf("Directory: user %s does not resolve via NSS; denying", user),
			"Access denied: no directory identity for this user."
	}
	return true, "", ""
}

// nssLookup reports whether the user resolves through SSSD. It queries the
// sss NSS service explicitly (getent -s sss) so that local-only /etc/passwd
// accounts do NOT satisfy the directory identity gate: the documented boundary
// is "SSSD and the directory own identity", and a plain `getent passwd` would
// also accept `files` entries, letting a same-named local account bypass
// directory revocation (PDA-SEC-001). A short timeout guards against a hung
// SSSD.
//
// getent exits 2 for "key not found" (found=false, err=nil); any other failure
// (timeout, SSSD down, exec error) is returned as err so callers can log an
// outage instead of claiming the account does not exist.
func nssLookup(username string) (found bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "-s", "sss", "passwd", "--", username).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 2 && ctx.Err() == nil {
			return false, nil
		}
		return false, err
	}
	// Only the entry of exactly this name counts: getent answers an all-digit
	// key with the entry of that UID.
	return nssAnswerMatches(out, username), nil
}

// deny prints a standard hard-deny message to the SSH client and waits for
// Enter (the prompt makes OpenSSH display the batched info lines). Whether the
// answer arrives changes nothing: the login is denied either way.
func (f *authFlow) deny(reason string) {
	f.io.info("------------------------------------")
	f.io.info("%s", reason)
	f.io.info("Contact your administrator.")
	f.io.info("------------------------------------")
	_ = f.io.prompt("Press Enter to disconnect... ")
}
