# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.7.1] - unreleased

Fixes from a review of 0.7.0. The sshd drop-in and `sssd.conf` stay as they
are; an upgrade needs no manual step.

### Security
- **Toolchain bumped to Go 1.27.4.** govulncheck flagged one standard library
  advisory in 1.27.3 (GO-2026-6859, net/http: an HTTP/1 server crash through a
  header race in `MaxBytesReader`), fixed in 1.27.4. The helper runs no HTTP
  server; the bump keeps the scan of the release clean.

### Fixed
- The helper stops when the SSH client disconnects at the "press Enter"
  prompt. Before, it lost its parent, took the end of its input for the
  answer and polled the identity provider for up to `auth_timeout`; a code
  approved in that time was logged as `Directory auth OK` and stored a cached
  session although no SSH session existed. Now the helper logs
  `Device flow: the SSH client went away at the prompt (<reason>); aborting`
  and exits 1, and the PAM module has the kernel end the helper together with
  the sshd process that started it.
- After Enter the first token request goes out at once. Before, every
  interactive login waited one poll interval (5 s) before it asked the
  identity provider for the token.
- Token polling survives transient failures: a network error, an HTTP 5xx,
  408 or 429 and an error page that is no OAuth error document (a reverse
  proxy's 502, for example) are retried with a growing wait (the poll
  interval, doubling up to 30 s, never shorter than the poll interval) until
  `auth_timeout`. Before, the first such
  failure ended the login with `poll token: …` or `parse error response`. At
  the timeout the log names the last failure:
  `device authorization timed out (last failure: token endpoint answered status 503)`.
- With `required_acr`, a refreshed token without an accepted `acr` no longer
  ends in a hard deny on a known address. The helper removes the cached
  session and starts the device flow, where a new sign-in can reach the
  level. A missing role stays a hard deny, and so does an `acr` finding after
  the device flow.
- A login name or group member name that starts with `-` never reaches a
  command line: the login and the account phase deny it, `--check` reports
  it and leaves it out, and `getent`, `busctl` and `sss_ssh_authorizedkeys`
  get every name after `--` (busctl reads options anywhere on its command
  line, so such a name in the directory changed what busctl did as root).
- The directory identity check accepts an answer of `getent` only when it
  carries the requested name. `getent` answers an all-digit name with the
  entry of that UID, so the check passed for a name that is no directory
  user. The same rule now applies to the ID-map check of `--check` and to
  the search for local accounts that shadow a directory user. A login name
  in another case than the directory entry (`Alice` for `alice`, which a
  case-insensitive SSSD domain such as the `ad` profile resolves) is refused
  at this check too; before, it failed later, at the comparison with the
  user name in the token.
- `--check` reads `AuthenticationMethods` the way sshd does: every
  alternative (alternatives are separated by whitespace) must contain
  `publickey` and `keyboard-interactive:pam`. Before,
  `publickey keyboard-interactive:pam`, where a space took the place of the
  comma and either factor is enough, was reported as `(2FA)`.
- `--check` asks sshd for the methods of every access-group and
  service-group member (`sshd -T -C user=<member>`) and warns about a member
  whose methods do not fit the tier, for example through a `Match` block in
  another sshd drop-in:
  `member(s) whose SSH factors do not fit their tier (…): alice (publickey)`.
  It fails when `UsePAM` or `KbdInteractiveAuthentication` is not `yes`:
  without PAM sshd runs neither the OIDC step nor the account phase.
- Keys in `config.json` that the loader does not know are reported instead of
  ignored without a word; a misspelled `required_acr` or `allowed_algorithms`
  switched that setting off unnoticed. A login logs
  `config: unknown key "<path>" is ignored` at WARN and goes on, so an
  upgrade never locks a host out over a stray key; `--check`, `--enable` and
  `--setup-ldap` fail on it. Keys of earlier versions (`directory_mode`,
  `ip_claim`, `create_user` and the like) stay silent.
- `allowed_algorithms` entries the verifier does not support (`rs256`,
  `PS256`, `none`) are reported the same way:
  `config: allowed_algorithms: "rs256" is not supported (supported: …)`.
  A list with no supported entry is a config error; before, such a config
  loaded and every login failed at the token check.
- The log path must be a regular file. The helper and the PAM module open
  `/var/log/pam-device-auth.log` without blocking and refuse a FIFO or a
  directory there as they refused a symlink before; a FIFO at the path
  blocked every login in `open(2)`. The reason in syslog reads
  `log path is not a regular file: … is a FIFO or a device`.
- The package's post-install script no longer runs `touch`, `chmod` and
  `chown` on the log path, which followed a symlink: where another user can
  write to `/var/log` (the syslog user on Ubuntu), a planted symlink made the
  next install or upgrade set mode `0640` and `root:adm` on the link target.
  The script now runs `pam-device-auth --prepare-log`, which works on the
  open file and neither chmods nor chowns a log whose mode and owner already
  fit; an append-only log refuses both.
- The helper removes only the mode bits of the log beyond `0640`. Before, it
  set every other mode to exactly `0640`, also a stricter `0600`.
- `--setup-ldap`, `--enable` and `--check` run with a fixed `PATH`
  (`/usr/sbin:/usr/bin:/sbin:/bin`). In a root shell without the sbin
  directories (`su` on Debian) `sshd -t` could not be started, which the
  setup reported as a rejected sshd drop-in and rolled back.
- The QR decision reads the client version from the journal of the current
  boot only and takes the newest line. Before, a reused PID could make the
  version line of an earlier connection decide.
- User names with a dot, an `@` or any other character outside
  `[A-Za-z0-9_-]`, and names of 33 to 64 bytes, get the cached login. Before,
  such a user (`john.doe`) went through the device flow at every login and
  the log showed `session cache error: invalid username for cache` twice.
  The cache file name is the user name with those bytes written as `%XX`
  (`john%2Edoe.json`); names that had a cache before keep their file, so no
  cached session is lost by the upgrade.
- The migration of a local account that shadows a directory user no longer
  carries over `root`, `adm`, `shadow`, `disk`, `staff`, `docker`, `lxd`,
  `incus` and `libvirt` (so far only `sudo`, `admin` and `wheel` were left
  out). These groups give root or near-root rights, which come from the
  directory in this setup. `--setup-ldap` and the preview of `--check` name
  the groups that are not carried over.
- On Rocky Linux and Fedora `--setup-ldap` keeps the authselect features of
  a host that already uses the `sssd` profile (`with-faillock`, `with-sudo`):
  it selects the profile again with these features and `with-mkhomedir`.
  Before, it always ran `authselect select sssd with-mkhomedir --force`,
  which dropped every other feature without a word. Another profile is still
  replaced, and the setup prints which one:
  `authselect: replacing profile "winbind"`.
- An `ES256`, `ES384` or `ES512` token passes only with a key on the curve of
  that algorithm (P-256, P-384, P-521; RFC 7518). Before, the verifier tied
  only the signature length to the algorithm. The log names the mismatch:
  `algorithm ES256 requires curve P-256, the key is on P-384`.
- A failed request to the identity provider puts at most 512 bytes of the
  answer into the log line. Before, an error page of up to 1 MiB went into
  one line.
- A commented-out `pam_device_auth.so` line in `/etc/pam.d/sshd` no longer
  counts as an active module. Before, `--check` reported
  `pam-device-auth is already active` and took the account phase for live on
  such a host, and the package scripts treated the stack as using the module.
- The rpm lists `sssd-dbus` as a weak dependency, as the deb does. The
  account phase reads a user's allowed addresses through it.

### Added
- `--check` reports a slow identity provider: `discovery answered in 80ms`,
  or a warning that names the usual cause, a name server in
  `/etc/resolv.conf` that does not answer properly. The helper resolves names
  with Go's resolver and waits 5 s for such a server, where `curl` and
  `getent` move on at once. A request that took more than 2 s is repeated once
  over a new connection; only two slow requests in a row are a warning
  (`discovery took 5.03s and 5.02s on two requests in a row`), a single one
  shows as `discovery answered in 180ms (the first request took 3.76s)`.
- A run by hand with `--debug` logs how long each request to the identity
  provider took (`Discovery took …`, `Device code request took …`,
  `Token refresh took …`, `JWKS fetch took …`).

### Changed
- Removing the package prints what stays behind when sssd is configured:
  `sssd stays configured: directory users can log in over SSH with their directory password if sshd allows password authentication; review PasswordAuthentication and /etc/sssd/sssd.conf`.
  The removal deletes the sshd drop-in that required the key and the OIDC
  step and keeps the directory identity, as before.
- The PAM module is built with `_FORTIFY_SOURCE=3` (before: 2); the C library
  now also checks the length of the read into the module's line buffer at run
  time. The module needs the same glibc version as before. A source build
  with a compiler before gcc 12 prints one warning and gets level 2.
- `make lint` runs staticcheck and shellcheck besides `go vet`, and the new
  `make analyze` compiles the PAM module once with gcc's static analyzer; CI
  runs both.
- Documentation corrected against the code:
  - sshd's `LoginGraceTime` (default 120 s) bounds the whole login and is
    shorter than the default `auth_timeout`; the configuration reference and
    the troubleshooting guide say how to raise it.
  - The `PAM_DEVICE_AUTH_*` environment variables only apply to a command run
    by hand. They never reached a login, because sshd runs the PAM
    conversation with an empty environment.
  - The user name the identity provider puts into `preferred_username` must
    not be changeable by users (SECURITY.md, Keycloak guide).
  - `iat` is a required claim; the helper reads no password; the PAM module
    has no `strtok_r`; sshd runs the PAM conversation of each connection in
    its own process.
  - Log lines and error texts in the troubleshooting and operations guides
    are the ones the code writes; the monitoring patterns match them.
  - Local non-root users cannot log in (man page); root's key login still
    runs the account and session stacks of `/etc/pam.d/sshd` (operations).

### Deprecated
- The `PAM_DEVICE_AUTH_*` environment variables. Set the values in
  `config.json`; 0.8.0 removes the variables.

## [0.7.0] - 2026-11-09

No fallbacks: an unsupported platform, a missing file or a failed step is an
error with a clear message, never a silent default. Upgrades from 0.6.x keep
LLDAP and Active Directory hosts working without a manual step, unless the
host is not a supported platform, its log file has a mode other than `0640`
that cannot be corrected, or its sshd config fails `sshd -t` (see Breaking).

### Breaking
- Supported platforms are exactly Ubuntu 24.04 or later, Debian 13 or later,
  Rocky Linux 9 and 10, and Fedora 44 or later (amd64), matched on the
  `ID` and `VERSION_ID` of `/etc/os-release`. Every other distribution or
  version is refused, including AlmaLinux, CentOS, RHEL and other clones and a
  match through `ID_LIKE` only. The package pre-install script refuses to
  install or upgrade before any file is unpacked, so an installed version
  stays as it is, and `--setup-ldap`, `--check` and `--enable` exit 1 before
  they read the config or change the host. The message is
  `unsupported distribution "<ID> <VERSION_ID>" (supported: ubuntu >= 24.04, debian >= 13, rocky 9/10, fedora >= 44)`.
  Logins (the PAM authentication and account phases) do not check the
  platform.
- `ldap.profile` is required (`"lldap"` or `"ad"`). A config with an `ldap`
  block without it fails `--check`, `--enable` and `--setup-ldap` with
  `config: ldap.profile is required ("lldap" or "ad")`. On upgrade the package
  runs the new `pam-device-auth --migrate-config` once, which sets
  `"profile": "lldap"` where 0.6.x read an unset, `null` or `""` profile as
  `lldap`; see Added. Configs that set `profile` (every Active Directory
  install) are not touched. If the migration fails, the post-install script
  fails with the reason and the step that completes the upgrade, and the
  config stays as it was.
- Package removal is refused while `/etc/pam.d/sshd` uses `pam_device_auth.so`
  and no valid `/etc/pam.d/sshd.original` exists (`.deb` and `.rpm`):
  `pam-device-auth: /etc/pam.d/sshd uses pam_device_auth.so and no valid /etc/pam.d/sshd.original exists; restore /etc/pam.d/sshd from your distribution's openssh-server package, then remove pam-device-auth`.
  The package and sshd stay as they are. Restore the file from the
  distribution's `openssh-server` package, then remove the package again.
- `--enable` backs up `/etc/pam.d/sshd` to `/etc/pam.d/sshd.original` as its
  first step and stops before it writes the sshd drop-in or the PAM stack when
  that fails; 0.6.x printed `[WARN] could not back up` and activated anyway.
  A missing `/etc/pam.d/sshd`, one that uses `pam_device_auth.so` while no
  backup exists, and an existing `sshd.original` that is empty, has no `auth`
  or `@include` line or uses `pam_device_auth.so` (the rule the package
  removal applies) are errors that name the restore from the
  `openssh-server` package. A valid `sshd.original` from an earlier
  `--enable` is kept.
- Logins: a log file that opens with a mode other than `0640` and cannot be
  set to `0640` (append-only with `chattr +a`, a filesystem without `chmod`)
  denies the login like a log that cannot be opened (for example immutable
  with `chattr +i`); 0.6.x ignored a failed `chmod`. The helper calls `chmod`
  only when the mode differs, so a log that already is `0640` keeps working
  when it is append-only. A host with an append-only log of another mode
  loses every non-root OIDC login after the upgrade until the flag is removed
  (`chattr -a`) or the mode is `0640`. The reason goes to syslog (`authpriv`,
  tag `pam-device-auth`), for example
  `pam-device-auth: cannot set log file mode 0640: chmod /var/log/pam-device-auth.log: operation not permitted; denying login (fail closed)`.
  Root's key-only login does not run the helper.
- `--pam-acct` denies non-root users, including key-only service accounts,
  when its log cannot be opened, or has another mode and cannot be set to
  `0640` (as above), and sends the reason to
  syslog (`authpriv`), ending in `; denying`; 0.6.x decided with a
  stderr-only logger. It exits 3, which the PAM module logs as
  `acct_mgmt: helper exited 3 (infra failure) for user <user> from IP <ip> — denying login (fail-closed)`.
  Root stays exempt.
- `--setup-ldap` aborts when the package index refresh (`apt-get update`)
  fails, for example on a dead third-party repository or an unreachable
  proxy, before it changes the host.
- Package upgrade with an active PAM configuration: a failing `sshd -t` or
  `systemctl restart` of sshd fails the post-install script, where 0.6.x only
  printed a warning. The message names the step that completes the upgrade
  once the sshd config is fixed: `dpkg --configure -a`, or
  `dnf reinstall ./pam-device-auth-<version>.x86_64.rpm` with the installed
  version (`dnf reinstall pam-device-auth` from a repository).

### Added
- Fedora 44 and later, with the RHEL-family setup (`.rpm`, `authselect`,
  `sshd.service`).
- `--migrate-config`: if `/etc/pam-device-auth/config.json` has an `ldap`
  block without `profile` (or with `null` or `""`), it writes
  `"profile": "lldap"` and prints
  `config: set ldap.profile = "lldap" (backup /etc/pam-device-auth/config.json.pre-0.7.0)`.
  The original is kept as `config.json.pre-0.7.0` with the same owner and
  mode; the new file is written atomically with the original's owner and mode
  and checked with the loader `--check` uses. Values are carried over as
  written; indentation and key order are not (keys come out sorted). A config
  without an `ldap` block, or with `"lldap"` or `"ad"`, is not touched. Any
  other profile, two keys that differ only in case, duplicate keys that the
  loader would read differently after the rewrite (it merges duplicate
  objects, the rewrite keeps the last one), a symlink, an existing backup file
  or unreadable JSON is an error and leaves the file as it is.
  The package's post-install script runs it on every install or upgrade that
  finds an existing config.
- `--setup-ldap` and `--check` check the login shell of directory users
  (`ldap.shell`, `/bin/bash` when unset): it must be an absolute path to a
  regular file that others may execute. `--setup-ldap` refuses before its
  first change to the host; `--check` reports a `[FAIL]`, also for a relative
  path that resolves from its working directory.
- Package pre-install and pre-remove scripts for the `.deb` and the `.rpm`
  (see Breaking).

### Changed
- `--setup-ldap` checks every step, and a failed step aborts the setup.
  Before the first file is written: the package index refresh (`apt-get
  update`, see Breaking), the package install, marking the packages as manually installed
  (`apt-mark manual`, `dnf mark install`, `dnf -y mark user`) and the presence
  of `sss_ssh_authorizedkeys` and the SSSD InfoPipe responder. After
  `sssd.conf` is written: the sync of its directory (the message says the new
  file was in place), its `chown`, the home directory wiring
  (`pam-auth-update --enable mkhomedir`, or `authselect select sssd
  with-mkhomedir --force` and `systemctl enable --now oddjobd`), nsswitch,
  sudoers, the sshd drop-in, masking the SSSD socket units, `systemctl enable
  --now sssd`, `sss_cache -E`, `systemctl restart sssd` and `systemctl
  reset-failed 'sssd-*'`. Each of these failures restores the previous
  `sssd.conf` (or removes the new one) and, once sssd runs on the new file,
  restarts sssd on the restored one. A failed local account migration
  (`userdel`, `gpasswd`, `chown`) stops the migration and keeps the new
  `sssd.conf`, because a migrated account resolves only through the
  directory. The `FAIL:` line names the failed command with its output, what
  the rollback did, and the changes that stay on the host
  (`still in place on the host: …`, for example the mkhomedir wiring, `sss` in
  `/etc/nsswitch.conf`, the sudoers and sshd drop-ins). After a failed
  `systemctl enable --now sssd` the list says `sssd enabled` only when
  `systemctl is-enabled sssd` answers `enabled`, nothing about it on
  `disabled`,
  ``sssd is masked (not enabled; `systemctl unmask sssd` to use it)`` on
  `masked`, and
  ``enable state of sssd unknown (check `systemctl is-enabled sssd`)`` on any
  other answer.
- A failed write of the discovery or JWKS cache is logged at WARN with the
  cache path (`Discovery cache write to /run/pam-device-auth/oidc/discovery.json failed, using the live document: …`,
  `JWKS cache write to /run/pam-device-auth/oidc/jwks.json failed, using the live key set: …`);
  the validated live data is used.
- sshd is restarted through the platform's unit only: `ssh.service` on Debian
  and Ubuntu, `sshd.service` on Rocky Linux and Fedora (`--enable` and the
  package scripts). The `--enable` message for a failed restart names the unit.
- Package post-remove: a failing `sshd -t` or `systemctl restart` fails the
  script (remove, purge) instead of printing a warning; the message names
  `systemctl restart <unit>`. The post-install side is under Breaking.
- Package post-install: a missing `/etc/pam-device-auth/config.json` on
  upgrade is an error (the template is installed on a first install only).
  The migration of a drop-in with `LogLevel DEBUG1` to `LogLevel VERBOSE` plus
  `LogVerbose` is an error when a step fails or `sshd -t` rejects the
  migrated drop-in (the previous one is put back). PAM counts as active (sshd
  is validated and restarted) only when `/etc/pam.d/sshd` uses
  `pam_device_auth.so`; an existing `sshd.original` alone, for example after
  an aborted `--enable`, no longer counts.
- `--setup-ldap` and `--enable`: an existing `sssd.conf`, sshd drop-in or
  sudoers drop-in that cannot be read is an error before it is replaced
  (`cannot read the existing <path>: …; nothing was written`); 0.6.x treated
  it as absent, so a rollback removed the file and its previous content was
  lost. When the directory
  sync after writing the sshd or sudoers drop-in fails, `sshd -t` or
  `visudo -c` still runs, a rejected file is rolled back, and an accepted one
  is reported as in place (`…; it passed sshd -t`).
- Package post-remove: `/etc/pam.d/sshd` is restored only from a verified
  `sshd.original`; a failed copy fails the removal and keeps the backup. A
  removal or purge validates and restarts sshd only when it removed the
  drop-in or restored `/etc/pam.d/sshd`; then a missing or failing sshd is an
  error. A host where neither existed (no `--setup-ldap`, no `--enable`) is
  removed without touching sshd.
- `--check`, `--setup-ldap` and `--enable` use the platform's paths for
  `sss_ssh_authorizedkeys` (`/usr/bin` on every supported platform) and the
  SSSD InfoPipe responder (`/usr/libexec/sssd/sssd_ifp`). A missing binary is
  a `[FAIL]` or an abort that names the path and the package (`sssd-common`,
  `sssd-dbus`).
- `make deb`, `make rpm` and `make release` fail outside a Git checkout, where
  `git log` gives no commit time for `SOURCE_DATE_EPOCH`.
- Built with Go 1.27.3 (0.6.1: Go 1.26.10); govulncheck reports no findings.

### Removed
- Platform detection through `ID_LIKE`, and the Debian profile for every
  distribution it did not recognise.
- The implicit `lldap` for an unset `ldap.profile`.
- The search lists for `sss_ssh_authorizedkeys` and `sssd_ifp`.
- The restart of `sshd.service` after a failed restart of `ssh.service` (and
  the reverse).
- The post-remove edit of `/etc/pam.d/sshd` without a valid backup (strip
  `pam_device_auth.so`, insert `@include common-auth`/`system-auth` or
  `auth required pam_unix.so`).
- Skipping `sshd -t` or the restart in the package scripts when `sshd` or
  `systemctl` was not found, and the post-install warning for old Ubuntu and
  Debian versions (replaced by the pre-install refusal).
- The stderr-only logger of `--pam-acct` when the log could not be opened.
- The fixed `SOURCE_DATE_EPOCH` outside a Git checkout, and `unknown` as the
  package version in post-install messages.

## [0.6.1] - 2026-11-08

### Security
- Built with Go 1.26.10: `crypto/x509` distrusts compromised intermediate
  certificates (GO-2026-6809). The helper verifies the identity provider's
  TLS certificate with it when it fetches the discovery document and the JWKS.

### Fixed
- Profile `ad` with `ldap.kerberos`: sudo and `passwd` failed for users whose
  UPN carries the lower-case DNS domain as its realm (`alice@example.com`),
  which is how AD returns it; SSSD found no KDC for that realm. The generated
  `sssd.conf` now sets `krb5_use_enterprise_principal = true` and
  `ldap_force_upper_case_realm = true`, as SSSD's own ad provider does: SSSD
  treats the UPN as an enterprise principal and upper-cases the realm. The
  `lldap` profile and `ad` without `kerberos` are unchanged. The package
  upgrade keeps the existing `sssd.conf`: on a host with `profile` `ad` and
  `kerberos`, run `pam-device-auth --setup-ldap` once after the upgrade (it
  rewrites `sssd.conf` and restarts SSSD; `--enable` is not needed again).
- `--setup-ldap` and `--check` reject `ldap.kerberos.keytab` with an IP
  address as the host of `ldap.uri` (IPv4 or IPv6, with or without port):
  GSSAPI uses the `ldap/<host>` service principal, so the bind cannot work.
  Name the DC by its host name; the name must resolve on the host.
- `--check` no longer reports an emergency path for root that does not exist:
  a `root_login_sources` address counts as the key path only if its effective
  `AuthorizedKeysFile` is not `none` (in addition to `prohibit-password` and
  `AuthenticationMethods publickey`). An address that allows root while its
  `AuthorizedKeysFile` is `none` is a warning that names the missing
  `AuthorizedKeysFile .ssh/authorized_keys` line and the addresses where the
  key path works, and with `root_login` `key` `--check` warns when root's own
  `AuthorizedKeysFile` is `none`. The example Match block in
  `docs/configuration-reference.md` now sets
  `AuthorizedKeysFile .ssh/authorized_keys`: the drop-in sets
  `AuthorizedKeysFile none` for everyone else.
- QR auto-detection decides per SSH client on every server: a client that
  escapes UTF-8 (for example Win32-OpenSSH) no longer gets an unreadable QR
  code on OpenSSH 10 servers. Distribution builds (Ubuntu, Debian, Fedora, Red
  Hat), PuTTY and plain OpenSSH 10 or later get the QR; Win32-OpenSSH, plain
  OpenSSH < 10 and unknown clients get link and code only. The sshd version is
  no longer read.
- `--check` on OpenSSH 10.5 (Fedora 45): `sshd -T` prints no
  `authorizedkeysfile` line for `AuthorizedKeysFile none`, and `--check` now
  reads that as `none` instead of reporting an empty value.
- Fedora: `--setup-ldap` marks the SSSD packages with `dnf -y mark user` (dnf5
  has no `dnf mark install` and asks for confirmation without `-y`), so
  `dnf remove pam-device-auth` keeps SSSD installed.

### Changed
- The comments of the sshd drop-in no longer name LLDAP for every profile
  ("from the directory via SSSD"), and the QR comment no longer limits the
  client version line to OpenSSH < 10; the next `--setup-ldap` rewrites the
  drop-in, its directives are unchanged. `--help` describes `--setup-ldap`
  without naming a directory product. With a keytab bind the `--check`
  access group line ends in `SSSD↔LDAP path OK (GSSAPI)` instead of
  `SSSD↔LDAP↔CA path OK`: no CA certificate is involved.
- `docs/active-directory-setup.md` and `docs/configuration-reference.md`
  describe the keytab bind's host name requirement, that a password change of
  the service account invalidates the keytab, and how to build a keytab with
  `ktutil` (`addent -password … -f`, key version from
  `msDS-KeyVersionNumber`) without changing anything in AD.
- `--check` shows a migration preview: one warning per local account that
  shadows a directory user, with what `--setup-ldap` will do (migrate it, the
  local groups it keeps and the home it re-owns, or skip it because of running
  processes). The warnings do not block `--enable`; the lookup goes through
  SSSD, so the preview needs an SSSD that already resolves the directory.
  A home below `/home` that does not exist is shown as nothing to re-own.
- The device flow logs the detected SSH client and the QR decision at INFO
  (`Directory: SSH client "<version>", QR shown|hidden (client|configured)`),
  plus `Directory: QR not rendered, verification URL is <n> bytes (limit 84)`
  when the URL is too long for the QR.

## [0.6.0] - 2026-10-13

### Added
- Active Directory profile (`ldap.profile = "ad"`): `--setup-ldap` writes an
  SSSD configuration with `ldap_schema = ad`, ID mapping from the objectSid
  (optional `id_range` for containers), the access gate via SSSD's simple access
  provider (nested groups, any OU) and freely chosen attributes for the SSH key
  and the source-IP allowlist (`ldap.attributes`). See
  `docs/active-directory-setup.md`.
- `ldap://` URIs with mandatory StartTLS, a Kerberos keytab bind (GSSAPI, over
  `ldap://` with SASL sealing), and Kerberos (`ldap.kerberos`) for sudo and
  passwd; with `kerberos`, `--setup-ldap` also installs the SSSD Kerberos
  provider and the SASL GSSAPI plugin. There is still no cleartext option.
  The keytab bind needs an `ldap://` URI: it is protected by SASL sealing, not
  TLS, and the generated `sssd.conf` sets `ldap_id_use_start_tls = false`
  (SSSD 2.10 and later default to StartTLS, and AD and Samba refuse GSSAPI
  sealing inside TLS). `--setup-ldap` and `--check` reject a keytab with an
  `ldaps://` URI.
- `ldap.bind_password_file`, `ldap.ca_file`, `ldap.home`, `ldap.shell`.
  `--setup-ldap` and `--check` fail when `ldap.ca_file` is missing or not a
  regular file (a directory, for example). `ldap.ca_file` must be readable by
  the SSSD service user: where `sssd_be` runs as user `sssd`, a file below the
  0700 directory `/etc/pam-device-auth` is not readable; use
  `/usr/local/share/ca-certificates/` (Debian, Ubuntu) or
  `/etc/pki/ca-trust/source/anchors/` (RHEL family). `--setup-ldap` fails on a
  `bind_password_file` longer than 4096 bytes.
- `required_acr`: the helper denies tokens whose `acr` claim is missing or not
  in the list, after the device flow and after every refresh.
- `root_login_sources`: `--check` evaluates root's sshd policy for these client
  addresses (Match Address blocks).
- `--check` reports the directory transport (`LDAPS`, `StartTLS`, `GSSAPI with
  SASL sealing`), the profile, `ca_file`, the Kerberos realm and KDC and the
  keytab permissions, and fails when `ldap.profile` is neither `lldap` nor
  `ad` or a directory user's UID or GID is outside the host's ID map
  (unprivileged containers).

### Changed
- `--setup-ldap` migrates local accounts that shadow a directory user without
  killing processes: accounts with running processes are skipped with a
  warning, local supplementary groups (except sudo, admin, wheel) are kept, and
  only files that belonged to the old IDs are re-owned.
- `ldap.bind_dn` must consist of `[A-Za-z0-9 ._=,@\-]` (a DN, a UPN or a
  down-level logon name), and every `ldap` value rejects all control
  characters, not only line breaks. A `bind_dn` with other characters now fails
  `--setup-ldap`.
- The rendered `sssd.conf` no longer contains `config_file_version = 2`.

## [0.5.15] - 2026-10-13

### Security
- **Toolchain bumped to Go 1.26.9.** govulncheck flagged nine standard
  library advisories on the OIDC/JWKS fetch path in 1.26.8 (GO-2026-6603,
  GO-2026-6605, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6613,
  GO-2026-6617 net/http, GO-2026-6608 net/textproto, GO-2026-6607
  crypto/tls), all fixed in 1.26.9.

### Changed
- The repository CI also checks every file for private data (a leak gate with
  patterns kept outside the repository; on forks and GitHub it runs its
  self-test only) and can run on a self-hosted runner.
- `--check` warns when sshd runs with `UseDNS yes`. sshd then passes the
  client host name instead of its address to PAM, and the account-phase IP
  gate denies every user with a `clients` allowlist.
- The account-phase section of `docs/architecture.md` no longer claims that
  sudo passes the IP gate: the module is wired into `/etc/pam.d/sshd` only.
- `docs/keycloak-setup.md` explains how to require a strong factor in the
  device flow. Keycloak ignores the client's minimum ACR and requested ACR
  values for the device grant (CVE-2026-105305); a browser flow override with
  one Level of Authentication condition, a passkey and no cookie step enforces
  it. The guide keeps the `acr` scope instead of recommending its removal and
  names Keycloak 26.7 as the tested version.

### Fixed
- `--check` accepted the IP allowlist attribute only as
  `ldap_user_extra_attrs = clients:clients` and refused activation otherwise.
  A directory that keeps the allowlist in another attribute
  (`clients:<attribute>`) now passes; the account phase always read it under
  the name `clients`.
- A device login without a refresh token from the identity provider stored the
  client IP for the cached login, so the next login from that IP spent a round
  trip to the identity provider on a refresh that could not succeed, and a
  session from an earlier login kept working from the new IP. Such a login now
  caches nothing and removes an earlier session of the user.
- The `.deb` declares `Conflicts` and `Replaces: keycloak-ssh-auth`. Removing
  the predecessor package restores `/etc/pam.d/sshd.original`, the same backup
  `--enable` uses, and so deactivated pam-device-auth when it was removed
  later. apt now removes it before pam-device-auth is configured.

## [0.5.14] - 2026-10-03

### Changed
- Documentation, code comments and tests use the documentation address ranges
  from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and
  `example.com` for all example addresses and directory names.

## [0.5.13] - 2026-10-03

### Changed
- The sshd drop-in no longer raises sshd to `LogLevel DEBUG1`. It now sets
  `LogLevel VERBOSE`, which logs the key fingerprint of accepted and rejected
  keys, and `LogVerbose kex.c:kex_exchange_identification():*`, which logs the
  client version line that QR auto-detection on OpenSSH < 10 needs. Package
  upgrades replace the old `LogLevel DEBUG1` line in an existing drop-in,
  validate the result with `sshd -t` and keep the old file if sshd rejects it.

### Fixed
- The RHEL profile pinned `/etc/pki/tls/certs/ca-bundle.crt` as the CA bundle for
  `ldap_tls_cacert`. Fedora 44 no longer ships that file, so SSSD could not start
  TLS to the directory, stayed offline and `--enable` refused to activate. The
  profile now uses `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, which
  exists on Rocky Linux 8, 9, 10 and Fedora.
- The login tests read the host clock from the whole ssh output. A client newer
  than the host's sshd prints a key exchange warning first (seen against Rocky
  Linux 9), which made the tests fail. They now read the last line.
- On Debian and Ubuntu, `sssd-common` enables the socket units of the SSSD
  responders (`sssd-nss.socket`, `sssd-pam.socket`, `sssd-pam-priv.socket`,
  `sssd-ssh.socket`) by preset. The sssd.conf written by `--setup-ldap` starts
  these responders from its `services` line, so the sockets failed at every
  boot ("socket-activated but still mentioned in the services line") and
  systemd reported the host as degraded. `--setup-ldap` now disables, stops and
  masks the socket units of the responders in the `services` line and resets
  the failed state of all `sssd-*` units after restarting sssd, which also
  clears an `sssd-ifp` that D-Bus started during the reconfiguration. On the
  RHEL family the sockets are disabled and nothing changes. `--check` warns
  when such a socket unit is enabled or failed.

## [0.5.12] - 2026-10-01

### Added
- Login tests (build tag `login`): real SSH logins against a host in directory
  mode as a fixed set of directory test users. They check that key-only service
  accounts, the NOPASSWD group and the source IP allowlist work, that a user
  without a group, without a key, with an unparseable key, with someone else's key
  or with a source IP outside the allowlist is refused for the logged reason, and
  that a user of the OIDC tier reaches the device flow prompt. CONTRIBUTING.md
  describes the users and the host setup. CI runs them against a dedicated host
  after each release-candidate deploy.
- The integration test for `--check` accepts the warnings a test host lists in
  `/etc/pam-device-auth/ci-known-warnings` and fails on any other warning.

### Fixed
- Debian and Ubuntu hosts did not get `sssd-tools`, which provides `sss_cache`.
  `--setup-ldap` expires the SSSD cache with `sss_cache` and the revocation
  procedure in the documentation uses it, but the command did not exist there, so
  the expiry silently did nothing and the cache kept serving the old value for up
  to 10 minutes. `--setup-ldap` now installs `sssd-tools` on Debian and Ubuntu as
  well, and the documentation names the package and a way to wipe the cache
  without it.

## [0.5.11] - 2026-10-01

### Fixed
- On the RHEL family, `dnf remove pam-device-auth` removed `sssd-dbus` as an
  unneeded dependency while `sssd.conf` still enabled `ifp`. The next restart of
  sssd then failed with `Could not restart critical service [ifp]` and took the
  directory identity of the host with it. `--setup-ldap` now installs
  `sssd-dbus` with the other SSSD packages and marks them as explicitly
  installed (`dnf mark install`, `apt-mark manual`), because installing a
  package that is already present as a dependency does not change its install
  reason. `--check` reports an enabled `ifp` service without the `sssd_ifp`
  binary as a blocker. A host set up with an earlier release picks this up by
  running `--setup-ldap` again, or by running `dnf mark install sssd-dbus` once
  (see the troubleshooting guide).
- The documentation said that the `ifp` responder ships in `sssd-common` on the
  RHEL family. It is the `sssd-dbus` package there too.

### Added
- `root_login` in `config.json`: `"key"` (the default, same as before) keeps
  root's own SSH key as the emergency path; `"disabled"` makes the sshd drop-in
  set `PermitRootLogin no` and omit the root block, so root cannot log in over
  SSH. `--setup-ldap` and `--enable` apply it, and `--enable` re-renders a
  drop-in that does not match. `--check` compares the effective sshd policy with
  the setting: with `"disabled"` a root that sshd still allows is a blocker, and
  with `"key"` a root that sshd refuses is a warning. The troubleshooting guide
  explains how to get root back and how a drop-in that sorts earlier overrides
  the setting.

## [0.5.10] - 2026-10-01

### Security
- The OIDC metadata cache no longer trusts what it finds on disk: an entry is
  read with `O_NOFOLLOW` and only when it is a regular file owned by the
  running user that group and others cannot write; a symlinked, foreign-owned
  or group/other-writable cache directory is refused. `Save` tightens an
  existing cache directory to 0700. A FIFO at the cache path does not block
  the login (the open is non-blocking). Every failure is a cache miss (live
  fetch), never a denial.

### Changed
- The copyright line in LICENSE names the years of the project history, 2025 to 2026
  (it said 2024; the first commit is from May 2025).
- The README is restructured around the product: what it is and why, how it
  works with the layer graphics, features, requirements, a shorter quick start,
  a documentation index and the known limitations. The LLDAP numbering and
  data model stay in `docs/ldap-directory-setup.md`.
- The public documentation under `docs/` (not the review and planning
  notes) is published with each release, and the docs no longer name
  site-specific infrastructure.
- SECURITY.md also points to GitHub's private vulnerability reporting, which is
  enabled for the repository.
- SECURITY.md promises what the other NKIT projects promise: acknowledgement
  within 7 days, a fix within 90 days and a coordinated disclosure date
  (it said 48 hours before).
- The security contact is `security@nk-it.cloud` (SECURITY.md, man page). The
  package maintainer is `Norbert Krucky <developers@nk-it.cloud>` in the deb
  and rpm metadata and in the man page, and the release commit on GitHub is
  authored by `NKIT CI <developers@nk-it.cloud>`.

### Added
- Integration tests (build tag `integration`) that run on a real host as root
  against SSSD, `busctl` and `sshd`: installed version, `--check`, NSS lookup,
  InfoPipe allowlist reads, the `--pam-acct` decisions, the effective sshd
  policy, the PAM stack and the cache permissions. They take users and groups
  from the host's own config. CI runs them on the test hosts after each
  release-candidate deploy, and runs the unit tests as root on all of them as
  well, so the ownership-guard tests no longer skip.
- A CI workflow for GitHub (`.github/workflows/ci.yml`): format, version
  consistency, build, tests with the race detector, vet and `govulncheck` on
  every push to `main` and every pull request, plus a check that every relative
  link and heading anchor in the public documentation resolves. The README shows
  its status.

## [0.5.9] - 2026-10-01

### Added
- Root-only on-disk cache for the OIDC discovery document and the JWKS in
  `/run/pam-device-auth/oidc/` (tmpfs, directory 0700, files 0600, 10 minute
  TTL). A login with a warm cache needs no metadata round trips: the
  cached-refresh path drops from 3 HTTPS requests to 1, the device-code path
  from 4 to 3. Cached bodies are decoded through the same validation path as
  live responses (endpoint host pinning, issuer pin, key strength checks); a
  stale, unparsable, foreign-issuer or invalid entry falls back to a live
  fetch. Failed fetches are never cached. `--check` always fetches live.
- Signing-key rotation: when the token `kid` is missing from a cached key
  set, the JWKS is refetched live exactly once and validation retried. No
  other validation failure triggers network traffic.

### Fixed
- `--check`: members whose `clients` attribute cannot be read through the
  SSSD InfoPipe now raise a `[WARN]` naming them. The account-phase IP gate
  fails closed for exactly these users.
- `--enable`: the sshd drop-in is rendered from the resolved
  `sss_ssh_authorizedkeys` path, with `sshd -t` validation and rollback,
  instead of copying the packaged template.
- `--setup-ldap` and `--check`: `ldap.uri` must use `ldaps://` with a host.
  The generated `sssd.conf` never enables StartTLS, so a plain `ldap://` URI
  would have sent `bind_password` in clear text.
- JWKS: RSA exponents longer than 4 bytes (or empty) are rejected instead of
  silently overflowing the exponent accumulator.
- Discovery and JWKS fetches apply a 10 s fallback deadline when the caller
  passes neither a context deadline nor an HTTP client timeout, so a server
  that keeps a response open cannot block a login indefinitely.
- Package removal (`.deb` and `.rpm`) deletes `/run/pam-device-auth/`, so
  cached refresh tokens do not linger until the next reboot.
- `make all` and `make release` run clean, build and test/deb serially.
  Under `make -j`, `clean` could previously delete the build directory while
  the build was running.
- `scripts/bump-version.sh` updates the man page `.TH` date and version; the
  CI version-consistency check now covers the man page.
- `--enable` exits non-zero and says "NOT fully active" when sshd could not
  be restarted, instead of printing "now active". The package `postinst`
  prints a warning instead of "upgraded successfully" in that case.
- `--enable` warns when the PAM backup could not be made: an unreadable
  source, an existing backup that already contains `pam_device_auth.so`, or a
  source that is already wired with no backup.
- `--setup-ldap` reports whether the previous `sssd.conf` was really
  restored, and restores it when a step after writing it (nsswitch, sudoers,
  sshd drop-in) fails.
- A corrupt per-user session cache file is removed (login) or replaced
  (update) instead of disabling the cached login for that user permanently.
  Session cache failures are logged as warnings, not at debug level.
- A token refresh that fails for a network or IdP outage keeps the cached
  session; only an HTTP 4xx rejection by the IdP clears it.
- Log lines for a failed `busctl` call include its stderr and name a timeout
  explicitly. A failing SSSD lookup of the SSH user is logged as an outage,
  not as "does not resolve via NSS".
- `--check` treats an unevaluable `sshd -T` as a blocker (it used to warn
  and let `--enable` proceed with unverified sshd factors), and reports
  members whose `sss_ssh_authorizedkeys` lookup itself failed as "key state
  UNKNOWN" instead of "no key".
- An entry of the `clients` allowlist that is neither an IP nor a CIDR is
  named in the account-phase log; it used to be skipped silently, so a typo
  denied the user without a trace.
- The auth phase reports an unopenable log file to syslog (`authpriv`) before
  denying the login. sshd discards the helper's stderr, so the denial was
  invisible.
- `--setup-ldap` ends with a list of its warnings (mkhomedir/authselect wiring,
  enabling sssd, ownership changes of migrated accounts) instead of a plain
  success message, and no longer prints "re-owned" for a failed `chown`.
### Changed
- Token validation applies one 60 s clock-skew window to `exp`, `nbf` and
  `iat` from a single clock reading. Previously only `iat` tolerated skew, so
  a host running a few seconds slow rejected fresh tokens on `nbf`.
- SSH client detection (for the QR auto-detect) uses one 2 s deadline for
  the whole parent-process walk instead of 2 s per `journalctl` call, which
  could add up to 8 s to a login. Setting `show_qr` explicitly skips the
  detection entirely.

### Security
- **Toolchain bumped to Go 1.26.8.** govulncheck flagged four standard
  library advisories on the OIDC/JWKS fetch path in 1.26.5 (GO-2026-6218
  net/url, GO-2026-6090 crypto/tls, GO-2026-5972 encoding/asn1, GO-2026-5026
  net/http idna), all fixed in 1.26.6 and later.
- **`--check` and `--enable` block when `sssd.conf` does not expose the
  `clients` attribute** (`ldap_user_extra_attrs = clients:clients` in the
  domain, `[ifp] user_attributes = +clients`). Without it the InfoPipe
  returns no allowlist and the account-phase IP gate treated every user as
  unrestricted without any warning.
- **`ldap.uri` is validated by `--check` as well as `--setup-ldap`.** The
  check also rejects comma or whitespace separated URI lists: SSSD reads
  `ldap_uri` as a failover list, so `ldaps://a,ldap://b` (accepted by
  `url.Parse`) could fall back to a cleartext bind of `bind_password`.
- `--enable` writes `/etc/pam.d/sshd` atomically; a crash or full disk can no
  longer leave a truncated PAM stack that also breaks the root break-glass
  login.
- `--check` verifies that the `AuthorizedKeysCommand` binary exists, and
  `--enable` re-renders an existing sshd drop-in that does not reference the
  resolved `sss_ssh_authorizedkeys` path (stale RHEL template path).
- The package no longer installs the sshd drop-in in `postinst`; only
  `--setup-ldap` and `--enable` write it, validated with `sshd -t`.

### Documentation
- README config example: the code fence is closed before the LDAP notes.
- `keycloak-setup.md`: describes the 10 minute discovery/JWKS cache, the
  single refetch on an unknown `kid`, and clearing it after a key revocation.
- `configuration-reference.md`: `ldap.uri` must be `ldaps://`; the claim that
  `ldap://` or StartTLS works is removed.
- Man page: only root is exempt from the `clients` check; `--check` scope
  updated.
- `upstream-check.yaml` parses the multi-line `govulncheck -json` stream and
  counts distinct OSV IDs with a called vulnerable function.
- `ldap-directory-setup.md`: the `clients` IP allowlist involves no OIDC
  token claim; it is read through the SSSD InfoPipe in the account phase.
  The revocation section distinguishes the login groups (`access_group`,
  `service_account_groups`) from the sudo groups (`admin_group`,
  `nopasswd_sudo_groups`).
- `configuration-reference.md`, `ldap-directory-setup.md`: the production
  template guidance points to `configs/config.json`.

## [0.5.8] - 2026-07-12

### Fixed
- Restricted the PAM account-phase break-glass exemption to root. A local
  `/etc/passwd` entry can no longer exempt a same-named directory identity from
  its `clients` source-IP policy.
- Unexpected successful InfoPipe response shapes now fail closed instead of
  being interpreted as an unset, unrestricted `clients` attribute.
- Stable GitHub source releases now include `nfpm.yaml` and the RHEL PAM
  template required to reproduce the published RPM.

### Documentation
- Distinguished package removal as an SSH emergency rollback from a full host
  rollback, which must also restore SSSD, NSS and authselect/mkhomedir state.

## [0.5.7] - 2026-07-12

### Changed
- The `clients` source-IP allowlist is now enforced only in the PAM account
  phase, which already covered every login (interactive and key-only service
  accounts) since 0.5.6. The redundant OIDC-token IP check was removed.

### Removed
- The `ip_claim` configuration field and the `PAM_DEVICE_AUTH_IP_CLAIM`
  environment override. A config that still sets `ip_claim` loads without error;
  the value is ignored. The Keycloak `clients` protocol mapper is no longer used
  and can be deleted.

## [0.5.6] - 2026-07-12

### Added
- **Rocky Linux 9 and 10 support** (amd64), alongside the existing Ubuntu
  24.04+/Debian 13+ support.
- **Service-account SSH tier (key-only, no OIDC)** via `service_account_groups`;
  opt-in passwordless sudo via `nopasswd_sudo_groups`; uninstall now removes
  the managed sudoers file.
- **The `clients` source-IP allowlist is now enforced for every SSH login**
  (including key-only service accounts) via the PAM account phase; previously
  only OIDC logins were IP-checked. Root break-glass is exempt.

### Packaging
- Packages are now built with nfpm from a single manifest, producing both the
  `.deb` and a new `.rpm` for Rocky Linux.
- The Debian package now recommends `sssd-dbus`, required by the SSSD InfoPipe
  responder that the account-phase IP allowlist reads.

### Documentation
- Completed the LLDAP setup guidance: every group referenced by the
  configuration (including `service_account_groups` and `nopasswd_sudo_groups`)
  needs a POSIX `gidNumber`, or SSSD does not resolve it and its members are
  locked out.

## [0.5.5] - 2026-07-11

### Fixed
- **Refresh-token rotation is serialized for concurrent SSH sessions.** The
  per-user cache lock now covers the complete load, IdP refresh, validation and
  save/delete transaction, preventing one process from deleting or overwriting
  another process's newly rotated token.
- **Atomic privileged-config writes are durable across crashes.** After replacing
  a config file, `--setup-ldap` now fsyncs the parent directory as well as the
  temporary file.

### Documentation
- Corrected the directory-setup guide to describe the automatic migration of
  same-name local accounts, including process termination and `userdel`.
- Clarified the setup/authentication boundary, SSSD-only troubleshooting command,
  README migration warning and current helper scripts.
- Added the current structured `--check` output, warning semantics and preflight
  links across the README, install, Keycloak, operations and troubleshooting docs.
- Reworked README and INSTALL around user goals and a safe step-by-step path;
  removed duplicated hand-managed PAM/sshd instructions in favor of package setup.
  The APT signing key is now verified before the repository is added.
- Corrected the security model for provider trust/outages, refresh-token IP
  semantics, LDAP transport protection and denial-of-service responsibility.
- Revalidated every public release guide against code, packaging, CI and the
  Ubuntu/Debian test matrix; corrected sudo-role semantics, environment
  overrides, revocation timing, uninstall scope and contributor requirements.

## [0.5.4] - 2026-07-11

### Security
- **Directory mode verifies the SSH user against SSSD only.** The identity
  gate now runs `getent -s sss passwd` instead of a plain NSS lookup, so a
  local-only `/etc/passwd` account can no longer satisfy the directory
  identity check; removing a user's directory identity reliably revokes
  access.
- **sshd drop-in disables local `authorized_keys` for non-root users**
  (`AuthorizedKeysFile none`). SSH keys are served exclusively from the
  directory via `sss_ssh_authorizedkeys`; a same-named local account with a
  local key can no longer supply the first factor. Root break-glass keys are
  unaffected (the `Match User root` block restores the local file). Note for
  upgrades: a package upgrade does not rewrite an existing drop-in at
  `/etc/ssh/sshd_config.d/10-pam-device-auth.conf`. On hosts that already had
  pam-device-auth installed, re-run `pam-device-auth --setup-ldap` (or update
  the drop-in by hand) to apply this hardening; `--check` now warns if
  `AuthorizedKeysFile` is not `none` for non-root.
- **Toolchain bumped to Go 1.26.5** for the crypto/tls and os stdlib security
  fixes (crypto/tls is on the active OIDC/JWKS fetch path).

### Fixed
- **Session cache files are safe against concurrent writes.** Each write uses a
  unique fsynced temp file, and cache load-modify-save updates are
  serialized with a per-user lock. Full refresh-token rotation serialization
  followed in v0.5.5.
- **`--setup-ldap` writes system configs crash-safely.** `/etc/nsswitch.conf`,
  the sudoers drop-in and the sshd drop-in are replaced atomically; a
  previously valid sudoers drop-in is restored (not deleted) if validation
  fails, and an sshd rollback failure is reported instead of ignored.

### Documentation
- README and all docs reviewed for accuracy; removed the stale claim that
  revoking `ssh-access` "locks the local account" (directory mode has no
  local account; the login is hard-denied and the cached session cleared).

## [0.5.3] - 2026-06-10

### Security
- **OIDC discovery: the `http://localhost` development exception no longer
  bypasses the issuer host-pin.** Plain-http endpoints are accepted only when
  the issuer itself is loopback (`localhost`/`127.0.0.1`/`::1`); a tampered
  discovery document for a production HTTPS issuer can no longer point
  `jwks_uri` (the root of signature trust) at a local listener.
- **IdP-supplied verification URI and user code are sanitized before display.**
  C0/C1 control bytes (ANSI/OSC escapes) and raw newlines are replaced with
  `?` before the values reach the SSH client's terminal or the line-based
  PAM relay protocol, so a compromised IdP cannot inject terminal escapes or
  forge protocol lines.
- **C module: the client IP is taken exclusively from `PAM_RHOST`.** The
  `SSH_CONNECTION`/`SSH_CLIENT` environment fallbacks were removed; those
  variables never exist in the PAM phase under normal sshd, and any present
  value would be attacker-influencable input to the IP-allowlist check.
- **C module: a failed PAM conversation now aborts authentication**
  (`PAM_CONV_ERR`) instead of sending a phantom acknowledgement that started
  the device flow invisibly on broken/non-interactive PAM stacks.
- **C module: usernames over 255 bytes are rejected** before entering the
  process environment, and the helper's exit status is determined explicitly
  (`waitpid` errors fail closed instead of relying on `WIFEXITED(-1)`
  behaving as hoped).
- **`release.sh` matches the hardened release pipeline:** refuses to overwrite
  an already-published release tag and stages an explicit file allowlist for
  the public mirror instead of the whole `configs/` directory. The
  `make release` tarball likewise copies an explicit config list.

### Fixed
- **IP allowlist: exact entries now match across IPv4/IPv6 notation.** On
  dual-stack sshd a client arriving as `::ffff:192.0.2.10` matches the allowlist
  entry `192.0.2.10` (and vice versa) instead of being hard-denied.
- **`--setup-ldap`: the sssd.conf rollback path is now atomic** (temp file +
  rename), closing the same partial-write window the forward path already
  guarded against.
- **Invalid `PAM_DEVICE_AUTH_TIMEOUT` values are rejected** with an error
  naming the variable instead of being silently ignored.
- **`--debug` now works in any argument position**, including after
  `--check`/`--enable`/`--setup-ldap`.
- **`http://[::1]` accepted as development issuer** alongside
  `localhost`/`127.0.0.1`.
- **Docs: INSTALL.md's manual sshd example enforced only one factor.** The
  example now uses `AuthenticationMethods publickey,keyboard-interactive:pam`
  (comma = both factors required) and `MaxAuthTries 3`, matching the shipped
  configuration; stale log patterns in the operations guide and the man-page
  version were refreshed.

### Fixed
- **Cache username charset** now allows mixed case (`[a-zA-Z0-9_-]{1,32}`), so
  case-preserving LDAP/`preferred_username` values keep a working silent-refresh
  cache instead of falling back to a full device flow on every login. Path
  separators, dots and other metacharacters that could escape the cache
  directory remain excluded.
- **`AddIP` ignores the `unknown`/empty IP sentinels** instead of storing them.
  The cached-refresh path never matches `unknown`, so persisting it only wasted
  a slot in the 20-entry FIFO.
- **`--enable` warns on backup failure.** A failed write of
  `/etc/pam.d/sshd.original` is now surfaced as `[WARN]` instead of being
  silently swallowed behind a misleading "Backed up original PAM config"
  message; an existing backup is never overwritten.

### Security
- **Migrated predecessor config no longer left world-readable.** Upgrading from
  the legacy `keycloak-ssh-auth` package copied `keycloak-pam.json` (historically
  an OIDC `client_secret` / LDAP `bind_password`) to a `0644` file via a bare
  `cp`. It is now `chmod 600` / `chown root:root`, and `/etc/pam-device-auth` is
  created `0700`, so a migrated secret is no longer readable by local users.
- **Log lines are sanitized against ANSI/escape injection.** The Go logger now
  replaces ESC and all other C0/C1 control bytes (not just CR/LF) with `?`,
  matching the C module's `sanitize_for_log`, so an unauthenticated SSH
  username/host cannot inject terminal escapes into the root-owned log.
- **OIDC/JWKS/discovery response bodies are size-bounded** (1 MiB, fail-closed)
  instead of being read with unbounded `io.ReadAll`/decoder. Removes a
  memory-exhaustion vector from a hostile (host-pinned) issuer.

### Hardening
- **PAM `.so` built with FORTIFY_SOURCE, stack-protector-strong,
  stack-clash-protection and full RELRO/BIND_NOW.** The root-resident native
  artifact now matches the hardening already applied to the Go helper.
- **`--setup-ldap` writes `sssd.conf` atomically with rollback.** The new config
  is written via temp-file + `rename` and reverted to the prior known-good file
  if `sssd` fails to restart, matching the existing `sshd`/`sudoers` writers.
  A rejected config can no longer leave SSSD down and lock out directory logins.
- **`postrm` removal no longer assumes `@include common-auth`.** On a PAM stack
  without `/etc/pam.d/common-auth` it now inserts `auth required pam_unix.so`
  instead, so uninstall cannot leave non-root SSH login unauthenticatable.
- Device/token HTTP client blocks redirects on the nil-client fallback path too.

### Build
- **Go toolchain bumped to 1.26.4** to clear two stdlib advisories flagged by
  `govulncheck`: GO-2026-5039 (unescaped inputs in `net/textproto` errors,
  reachable via the JWKS/token fetch path) and GO-2026-5037 (inefficient
  hostname parsing in `crypto/x509`). No source changes.
- **Reproducible `.deb`:** `gzip -9n`, `SOURCE_DATE_EPOCH`-clamped member mtimes
  and `dpkg-deb --root-owner-group` make the package byte-identical across
  builds from identical source.

## [0.5.2] - 2026-05-31

### Hardening
- **`--setup-ldap` directory-config validation** is now a single choke point
  (`validateLDAPConfig`) that closes injection gaps in the values written into
  `sssd.conf`/`sudoers`. Previously `user_search_base` and `group_search_base`
  bypassed the newline guard entirely (sssd.conf directive injection, e.g. an
  `ldap_access_filter = (objectClass=*)` override nullifying the per-host login
  gate, or `ldap_tls_reqcert = never` downgrading directory TLS), and the
  group/DN fields were only blocklist-checked. Now: newlines rejected in **all**
  fields; `access_group`/`admin_group` must be bare Unix group names
  (`[A-Za-z_][A-Za-z0-9_-]*`, blocking sudoers-grammar payloads such as a
  smuggled `NOPASSWD: ALL`); `base_dn`/`user_search_base`/`group_search_base`
  constrained to a DN charset (`[A-Za-z0-9 ._=,-]`, blocking LDAP-filter
  break-out like `)(uid=*`).
- **OIDC discovery endpoints are pinned to the issuer host.** `jwks_uri`,
  `token_endpoint`, and `device_authorization_endpoint` must now share the
  issuer's hostname, so a tampered discovery document that keeps a legitimate
  `issuer` can no longer redirect JWKS retrieval (the root of signature trust)
  to an attacker-controlled host.
- **JWKS key-parameter sanity checks.** RSA keys with a modulus < 2048 bits or
  exponent < 3 (e.g. the trivially-forgeable `e=1`) and EC points not on the
  named curve are now rejected before a key is ever used to verify a signature,
  as defense-in-depth against a poisoned JWKS response.

### Build
- **Go toolchain bumped to 1.26.3** to clear two standard-library advisories
  flagged by `govulncheck` against 1.26.2: GO-2026-4971 (`net` Dial/LookupPort
  NUL-byte panic, Windows-only) and GO-2026-4918 (`net/http` HTTP/2 transport
  infinite loop on a malformed `SETTINGS_MAX_FRAME_SIZE`). Both are reachable
  only via the JWKS fetch path and neither is exploitable on a Linux-only module
  talking to a trusted Keycloak, but the toolchain bump keeps the security gate
  green. No source changes.

## [0.5.1] - 2026-05-29

### Changed
- `--check` is now a full pre-activation preflight. In addition to config validity
  and OIDC discovery it verifies issuer match, the directory path
  (`sss_ssh_authorizedkeys` present, `/etc/sssd/sssd.conf` present, `sssd` active,
  the access group resolves via NSS (which exercises the whole SSSD↔LDAP↔CA chain)
  and every access-group member has a **valid** `sshPublicKey`, validated with
  `ssh-keygen -l`, flagging members with no key or an unparseable key who would be
  locked out of non-root login), and the sshd factors (`AuthorizedKeysCommand` → `sss_ssh_authorizedkeys`, non-root
  2FA, root `publickey` break-glass). Each item reports `[OK]/[WARN]/[FAIL]`; blockers
  exit non-zero so lockout risks are caught before `--enable`.
- `--enable` now actually runs that preflight and refuses to activate on any blocker
  (it previously only loaded config + tested OIDC discovery, despite the help text
  promising "runs --check first"), so activation can no longer wire PAM/sshd against
  a MITM'd issuer or a directory that cannot resolve users / serve keys.

### Hardening
- **C PAM module:** removed the now-unreachable `PROMPT:`/password-relay branch
  (directory mode never prompts for a password, since the SSH key factor is handled by
  sshd, the sudo password by `pam_sss`); the env-whitelist backing arrays now derive
  their size from the whitelist (was a hardcoded `9`, a latent stack overflow if the
  list grew); the child closes all fds ≥ 3 up to the descriptor limit (was `1024`).
- **logger:** open the log with `O_NOFOLLOW` (symlink-redirect defence) and escape
  newlines in logged values (log-line injection).
- **qr:** cap the encoder at version 6 and error above it. Versions ≥ 7 require the
  ISO/IEC 18004 version-information blocks this encoder does not emit (they would be
  undecodable), and fix the version-selection off-by-one. The device-auth path gates
  URLs to ≤ 84 bytes, so generated QR codes were never affected in practice.

### Fixed
- Uninstall (`dpkg -r`/`-P`): the postrm restore guard only matched a literal `^auth`
  line, so it never recognised the distro-default sshd PAM (which authenticates via
  `@include common-auth` and has no `auth` line) and left a dangling `pam_device_auth.so`
  reference in `/etc/pam.d/sshd` after removal. It now restores an `@include`-based
  original, refuses a backup that itself contains `pam_device_auth.so`, and as a fallback
  strips the module while keeping `@include common-auth` in place, so SSH PAM is always
  left working.
- The shipped sshd drop-in (`configs/10-pam-device-auth.conf`) now carries the
  directory-mode 2FA directives (`AuthenticationMethods publickey,keyboard-interactive:pam`
  + `AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys`), identical to what
  `--setup-ldap` writes, instead of the legacy single-factor (`publickey keyboard-interactive`)
  config, so the package and the wizard are a single source of truth.

### Docs
- INSTALL.md and the man page note Ubuntu 26.04 LTS in the tested-OS list.

## [0.5.0] - 2026-05-29

Breaking release: **directory mode is now the only mode.** The legacy local-account
(`create_user`) path is removed entirely; pam-device-auth is purely the OIDC layer on
top of directory identity (LLDAP via SSSD/NSS).

### Removed (breaking)
- Legacy **local mode**: on-the-fly local user creation, `/etc/shadow` password
  verification (libxcrypt/CGO), account lock/unlock and the temporary-password machinery.
- Config fields `create_user`, `user_groups`, `admin_groups`, `force_password_change`
  and `directory_mode`. Identity is always directory-backed and `directory_mode` is now
  implicit. Deployed configs that still contain these fields remain valid (ignored).
- Go package `internal/user`, `verify_crypt.go` (CGO) and the related auth code paths
  (`tryCachedRefresh`, `deviceAuthFlow`, local password verification).

### Changed
- The Go helper is now **CGO-free and statically linked** (`CGO_ENABLED=0`), with no
  libxcrypt/libc runtime dependency for the binary; the C PAM shim remains the only
  native artifact (links `libpam` only).
- README: restored the APT-repository install instructions; clarified that LDAPS is
  recommended. Plain `ldap://` is accepted but unencrypted; the managed setup does
  not add StartTLS directives. Removed the "Operating modes" section. man page and all example
  configs updated to directory-only.
- `--setup-ldap` no longer requires a `directory_mode` flag; it runs from the `ldap`
  config block alone.
- `--check` and `--enable` now detect when pam-device-auth is already active
  (`pam_device_auth.so` present in `/etc/pam.d/sshd`) and report that instead of
  suggesting activation.
- `--setup-ldap` lists the local accounts it will migrate (userdel + re-own home)
  as a warning *before* acting, instead of only reporting after the fact.
- Defensive NSS-identity gate: the auth path denies (and never caches a token) if
  the SSH user does not resolve via NSS, restoring the pre-0.5 "no Unix identity →
  deny" invariant even if the module is wired without the matching sshd drop-in.

### Upgrade notes
- Make sure every SSH user has `uidNumber`/`gidNumber`/`sshPublicKey` in the directory and
  run `--setup-ldap` before relying on this version. There is no in-place local-account
  fallback: hosts still on the legacy path must migrate to directory mode.

## [0.4.0] - 2026-05-29

Major release: **directory-backed identity + two-factor SSH**. Includes all of the
unreleased 0.3.8 hardening below.

### Added: directory mode (`directory_mode: true`)
- Identity, groups, home directory, SSH keys and the sudo password come from an LDAP
  directory via **SSSD/NSS**; pam-device-auth becomes the OIDC SSH-login layer only.
  Fixes login on **OpenSSH 10.2+**, which refuses PAM for not-yet-existing local users.
- **Two-factor login** for non-root: `AuthenticationMethods publickey,keyboard-interactive:pam`.
  SSH key served from LDAP (`AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys`,
  `sshPublicKey`) **and** OIDC device grant. Root stays key-only (break-glass).
- **`--setup-ldap` wizard**: writes `/etc/sssd/sssd.conf` (rfc2307bis, ldaps,
  `ssh`/`auth`/`access` providers, `ldap_user_ssh_public_key`, `entry_cache_timeout`),
  `nsswitch` (`sss`), `pam_mkhomedir`, sudoers (`%<admin_group>`, visudo-validated) and the
  sshd drop-in; installs SSSD packages; idempotent.
- **Automatic migration** of pre-existing local accounts that shadow a directory user
  (userdel + re-own `/home/<user>` to the directory uid:gid; files preserved).
- New config: `directory_mode`, `ldap` block (`uri`, `base_dn`, `bind_dn`, `bind_password`,
  `access_group`, `admin_group`). Bind password only read at setup → written to root-only sssd.conf.
- sudo re-authenticates against the directory password (`pam_sss`, `auth_provider=ldap`) for
  `sudo_role`/`ssh-admin` members; no local passwords or `/etc/shadow`.

### Security
- Directory-mode auth reuses the full token validation (kid/alg-allowlist/iss/azp-aud/exp/iat/
  role/IP); revocation enforced via SSSD access filter + role check (bounded by cache TTL).
- Wizard rejects newline/LDAP-filter-metachar injection into sssd.conf; `ldap_tls_reqcert=hard`.
- The silent cached-refresh fast path now sits behind the mandatory SSH-key factor (no IP-only login).

### Docs
- README rewritten around directory mode and two-factor SSH
  (prerequisites, UID<65536 on LXC, numbering scheme, migration, revocation SLA, SSSD cache wipe);
  example configs updated for directory mode.

### Packaging
- `Recommends: sssd-ldap, libnss-sss, libpam-sss`; dropped obsolete `Conflicts/Replaces keycloak-ssh-auth`.

### Verified
- End-to-end on OpenSSH 9.6 / 10.0 / 10.2 (Ubuntu 24.04, Debian 13, Ubuntu 26.04) incl. a
  production host: 2FA login, migration (local → directory, files kept), sudo via directory
  password, DNS service unaffected, root break-glass intact.

## [0.3.8] - 2026-05-29

### Security / Docs
- **Auth-model documentation corrected**: README/SECURITY.md no longer claim "every session
  is verified by the IdP". `publickey` and `keyboard-interactive` are alternatives (OR), so a
  key-holding user bypasses OIDC by design (enables keyless onboarding). Documented that
  role-revocation, the OIDC IP-allowlist, and `usermod --lock` bind only the keyless/OIDC path,
  and that full revocation requires removing `authorized_keys`/the local account.
- **Algorithm pinning shipped in example configs**: `allowed_algorithms` set to `RS256` in
  the shipped examples (Keycloak/Okta/Auth0/Authentik), closing the algorithm-confusion window
  on a poisoned JWKS by default. `configuration-reference.md` documents the `ES256` case for
  ECDSA-signing realms.

### Fixed
- **sshd `MaxAuthTries` 1 → 3**: `1` disconnected clients after a single rejected agent key,
  before the OIDC `keyboard-interactive` method ran, breaking keyless onboarding and leaving no
  margin for a mistyped local password.
- **C module: `strtok` → `strtok_r`** in `get_client_ip`, removes non-reentrant static state.
- **Packaging: `sshd -t` before restart** in postinst/postrm, refuses to restart on invalid
  config, preventing a dropped SSH listener; stderr captured in a variable (no predictable temp
  path); postrm validates the PAM backup before restoring.
- **`config.json` ownership**: explicit `chown root:root` alongside `chmod 600`.
- **bump-version.sh**: anchored the `main.go` VERSION sed.

### CI / Supply chain
- syft installer pinned to its release tag and run from disk (no `curl|sh` from `main`).
- APT publish made atomic (`stable` never left empty on the success path).
- GitHub release **tags are now immutable** (workflow refuses to overwrite an existing tag).
- `SHA256SUMS` published with each release; manual install docs instruct `sha256sum -c`.

### Notes
- `LogLevel DEBUG1` is retained and **documented as required** for SSH-client QR auto-detection
  (`show_qr` is the opt-out for operators who want lower verbosity).

## [0.3.7] - 2026-04-20

Combined scope of the internal v0.3.6-rc1 and v0.3.7-rc1 release
candidates (both host-verified). Collapsed into a single 0.3.7 final.

### Security: PAM wrapper hardening

- **Sanitized child environment**: `clearenv()` prior to launching the
  Go helper with a minimal whitelist (`PAM_USER`, `PAM_RHOST`,
  `PAM_DEVICE_AUTH_*`) and a hardcoded
  `PATH=/usr/sbin:/usr/bin:/sbin:/bin`. Closes a code-injection vector
  where `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `IFS` inherited from sshd
  (via misconfigured `AcceptEnv` or a hostile init-unit environment)
  would propagate into the helper and get loaded at dlopen.
- **`pipe2(O_CLOEXEC)`**: replaces `pipe()` on both child-bound
  pipes. Prevents fd leakage into any concurrent fork+launch from
  another PAM module running inside the same sshd process.

### Security: JWT validation

- **`iat` claim required**: absence of `iat` is now a hard rejection
  instead of silently skipping the forward-clock check. All mainstream
  IdPs emit `iat`; closes the one path that previously bypassed
  timestamp validation.
- **Algorithm allowlist**: new optional config field
  `allowed_algorithms` (string array). When set, tokens whose `alg`
  header is not in the list are rejected before signature verification,
  closing the algorithm-confusion window on a hostile JWKS response.
  Default empty/unset = accept any supported algorithm (RS256/384/512,
  ES256/384/512). Recommended pin for Keycloak/Authentik/Okta:
  `"allowed_algorithms": ["RS256"]`.

### Security: network + filesystem

- **Strict no-redirect policy on OIDC/JWKS clients**: all outbound
  calls (discovery, token exchange, refresh, JWKS fetch) now set
  `CheckRedirect: http.ErrUseLastResponse`. Legitimate Keycloak/
  Authentik/Okta deployments never redirect these endpoints; blocking
  them closes a downgrade-to-http and cross-origin hijack window on a
  MITM with a misissued cert.
- **`.bash_profile` symlink-plant defense**: install now uses
  `O_WRONLY|O_CREATE|O_EXCL`. An existing file (or a symlink planted on
  a shared-home NFS mount) is detected, logged, and skipped instead of
  being followed or clobbered. Closes TOCTOU on pre-user-home access.

### Fixed

- **`auth_timeout` validator clamp 30-240** (was 30-600). The C PAM
  wrapper `SIGKILL`s the helper at `AUTH_TOTAL_TIMEOUT_S=300`, so any
  configured value above 240 was silently truncated mid-flow. 240
  leaves 60 s of headroom for child startup, PAM conversation round-
  trips, and process reap. Docs and in-C comment updated.
- **`role_claim` now supplements Keycloak roles instead of replacing
  them**. Previously,
  setting `role_claim` dropped the `realm_access.roles` and
  `resource_access.<client>.roles` lookup entirely, so deployments that
  relied on Keycloak-native roles AND a custom claim silently lost
  access.
- **`role_claim` dotted-path traversal**: `role_claim:
  "resource_access.ssh.roles"` now walks the nested payload as
  documented. Flat lookup still runs first so URL-style keys like
  `https://example.com/roles` keep working unchanged.
- **`create_user=false` enforcement**: helper now exits `2`
  (`PAM_PERM_DENIED`) before `cache.Save` when the OIDC-authenticated
  user has no local shadow entry. Previously it exited `0` and returned
  `PAM_SUCCESS` for a user that only the downstream `pam_unix` account
  phase could reject, leaving a cache entry on disk for an invalid
  identity. Locked accounts (hash prefix `!`) remain exempt: the
  unlock path above handles them.

### Supply chain

- **Reproducible Go builds**: `-trimpath -ldflags="-buildid="` added
  to `GO_BUILD_FLAGS`. Byte-identical binaries from identical sources;
  verified with repeated `make clean build` on the same host.
- **SBOM generation in release workflow**: syft (pinned to v1.42.4)
  emits both SPDX-JSON and CycloneDX-JSON for every release, attached
  to the GitHub release alongside the .deb. Syft scans both the Go
  binary dependency graph AND the C PAM module inside the .deb in one
  pass.

## [0.3.5] - 2026-04-16

### Security
- **JWT `kid` collision closed**: JWK entries with empty `kid` dropped at
  JWKS fetch; JWTs with empty header `kid` rejected at verification.
  Closes a forgery path where a kid-less token would silently match any
  empty-kid JWKS entry.
- **`iat` sanity check**: tokens with `iat` more than 60 s in the future
  (beyond NTP skew tolerance) are rejected.
- **Group-name validation**: `user_groups` / `admin_groups` entries must
  match `^[a-z_][a-z0-9_-]{0,31}$` before reaching `usermod -aG`. Blocks a
  misconfigured value like `"sudo,root"` from silently adding the user to
  both groups (shadow-utils splits `-aG` on commas inside a single arg).
- **PAM module reentrant timeout**: replaced process-global `SIGALRM` +
  `child_timed_out` / `timeout_child_pid` state with a per-call
  stack-local monotonic deadline and `poll()`-based read loop. Concurrent
  PAM auth calls in the same sshd process no longer clobber each other's
  timer; a child that hangs mid-stream (not just at `waitpid`) is now
  killed and reaped by the deadline.
- **Log file perms `0640 root:adm`**: previously `0644`. Log contains
  PII (usernames, emails, IPs, roles). Tightened via postinst, logrotate
  policy, runtime `Chmod` in the Go logger (for in-place upgrades), and
  the C PAM module's `O_NOFOLLOW` open.
- **Rebuilt with Go 1.26.2** (via `toolchain` directive), picks up four
  stdlib CVEs: GO-2026-4866 (`crypto/x509` excludedSubtrees case-sensitive
  auth bypass), GO-2026-4870 (`crypto/tls` 1.3 KeyUpdate DoS),
  GO-2026-4946 (`crypto/x509` inefficient policy validation), GO-2026-4947
  (`crypto/x509` chain-building unexpected work).

### Changed
- Cache-refresh transient failures (refresh / JWKS / token-validate) now
  log at `WARN` with reason before falling through to device flow;
  previously hidden in `INFO`.

## [0.3.4] - 2026-03-28

### Security
- **JWT algorithm/key-type binding**: RS256/384/512 requires RSA keys, ES256/384/512 requires EC keys; prevents key-confusion attacks
- **OIDC endpoint HTTPS enforcement**: all discovery, token, and device authorization endpoints validated for `https://` scheme
- **KnownIPs capped at 20** per user with FIFO eviction, prevents unbounded cache growth
- **Shadow TOCTOU elimination**: `/etc/shadow` read once per auth cycle (no race between check and use)
- **C module: fork/exec hardening**: `popen()` replaced with `fork/exec` + bidirectional pipes (removes shell from auth path)
- **C module: fd leak fix**: partial `pipe()` fd leak on error path closed
- **C module: SIGPIPE handling**: signal restored after child process communication
- **C module: waitpid timeout**: prevents indefinite hang if Go binary stalls
- **C module: log input sanitization**: no tokens, passwords, or unsanitized user input in logs
- **C module: password zeroing**: memory cleared regardless of PAM conversation result
- **C module: double-free fix**: conversation error path no longer frees response twice
- **IP bypass fix**: cached session validation corrected

### Added
- **OIDC IP allowlist** (`ip_claim`): optional JWT claim containing allowed IPs/CIDRs per user; centrally managed in the identity provider, cryptographically signed, supports plain IPs and CIDR notation
- **Hard deny via `PAM_MAXTRIES`**: IP/role denials use exit code 2 → sshd stops retrying immediately (no 3x password loop)
- **FLUSH on all denial messages**: IP denied, role revoked, and username mismatch messages are visible before disconnect (OpenSSH 10+ buffering)
- SSH client version detection in Go (`internal/sshclient`), PID-walk from parent upward to find client version in journalctl
- QR auto-detection: OpenSSH 10+ always shows QR (vis() fixed), OpenSSH 9.x uses client allowlist (Ubuntu, Debian, Fedora, PuTTY)
- QR version cap: URLs longer than 84 bytes skip QR generation (Version 5 ECC M limit)
- `FLUSH:` protocol for OpenSSH 10+ PAM info message buffering compatibility
- Batched PAM conversation: single `conv()` call eliminates extra Enter presses after auth
- Man page (`man/pam-device-auth.8`, section 8)

### Changed
- **`MaxAuthTries 1`** in default sshd config, prevents retry loops on denial
- QR detection rewritten: OpenSSH 10+ skip client detection entirely (vis() fixed in openbsd-compat); OpenSSH 9.x detects client via PPID journalctl lookup
- Multi-line temp password display uses batched FLUSH for correct rendering
- OSC 8 hyperlink escapes removed (broken through `strnvis` on Windows/Termux)
- Dead code removed (unused render guard, post-exit return, inlined `shouldShowQR`)

### Removed
- Post-auth SSO session banner (reverted, not delivered by OpenSSH keyboard-interactive)
- PID-based grandparent walk for client detection (replaced by parent-upward walk)

## [0.3.3] - 2026-03-22

### Security
- Rebuilt with Go 1.26: fixes 18 Go stdlib vulnerabilities (previously built with Go 1.22)

### Changed
- Go module path corrected to `github.com/NK-IT-CLOUD/pam-device-auth`
- Minimum Go version for source builds: 1.26

## [0.3.2] - 2026-03-21

### Changed
- Go module path aligned with the GitHub organization (NK-IT-CLOUD)

## [0.3.1] - 2026-03-21

### Added
- Auto-detect Win32-OpenSSH clients and skip QR code (broken Unicode in ssh.exe strnvis)
- `show_qr` config option: `true` (always), `false` (never), omit (auto-detect)
- SSH client version detection via journald (requires LogLevel DEBUG1)

### Changed
- Replace Unicode separators with ASCII for PowerShell compatibility
- sshd config uses LogLevel DEBUG1 by default (for client auto-detection)

## [0.3.0] - 2026-03-21

### Added
- IP-bound sessions: new client IPs require full device auth (browser confirmation)
- Known IPs stored per-user in cache (tmpfs, wiped on reboot)
- User lock/unlock: account locked on OIDC role revocation, unlocked on re-grant
- Temp password on user creation (eliminates double device auth on first setup)
- Password verification via crypt_r(3)/libxcrypt (replaces unix_chkpwd)
- Clear error messages for username mismatch and missing OIDC roles
- Detect locked accounts (! prefix in shadow hash)
- OIDC issuer cross-validation (MITM protection)

### Changed
- C PAM module rewritten: popen() replaced with fork/exec + bidirectional pipes
- PROMPT: protocol for secure password input via PAM conversation (echo off)
- Single PROMPT: per session (prevents social engineering)
- Password zeroed in memory after use
- Close inherited fds (3..1023) in child process
- pam_sm_acct_mgmt returns PAM_IGNORE (delegates to pam_unix)
- Thread-safe get_client_ip() with caller-supplied buffer
- CGO enabled for libxcrypt/crypt_r integration

### Fixed
- Authentication bypass: cached refresh tokens no longer accepted without local password
- unix_chkpwd broken on glibc 2.38+ (setgid fd sanitization), replaced with crypt_r
- User-writable ~/.password_set flag replaced with /etc/shadow hash check

## [0.2.0] - 2026-03-20

### Added
- `--check` command: validates config and tests OIDC provider connectivity before activation
- `--enable` command: activates PAM authentication after successful config check, restarts SSH
- Safe installation: fresh installs no longer auto-activate PAM, prevents lockout with default config

### Changed
- Upgrade installs preserve existing PAM activation and restart SSH automatically

## [0.1.1] - 2026-03-20

### Changed
- Root user authenticates via SSH key only (no OIDC required)
- `Match User root` added to default sshd config

## [0.1.0] - 2026-03-20

First public release. Generic OIDC Device Authorization Grant for SSH PAM authentication.

### Features
- OIDC Device Authorization Grant (RFC 8628) for SSH login
- Works with any OIDC provider: Keycloak, Auth0, Okta, Authentik
- Custom role claim extraction via `role_claim` config
- Refresh token caching in tmpfs for fast repeat logins (~200ms)
- Automatic user creation with configurable group membership
- Role-based group assignment: `sudo_role` + `admin_groups` for admin/user separation
- Automatic demotion: revoking `sudo_role` removes admin groups on next login
- QR code displayed during device authorization for easy mobile scanning
- Forced local password setup on first login via `.bash_profile` prompt (used for sudo)
- JWT signature verification via JWKS (RSA + ECDSA)
- Debian package with zero-config install
- stdlib-only Go binary, zero external dependencies

### Security
- Cryptographic JWT verification (RS256/384/512, ES256/384/512)
- OIDC Discovery fail-fast (no silent degradation)
- Username validation (path-traversal protected)
- Atomic cache writes in tmpfs (ephemeral on reboot)
- Token refresh validates at provider on every cached login
