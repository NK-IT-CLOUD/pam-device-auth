package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// idMapRange is one line of /proc/self/uid_map or gid_map: IDs
// [inside, inside+count) exist in this user namespace.
type idMapRange struct{ inside, count int64 }

// parseIDMap parses uid_map/gid_map content ("inside outside count" per line)
// and skips malformed lines.
func parseIDMap(content string) []idMapRange {
	var out []idMapRange
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		inside, err1 := strconv.ParseInt(f[0], 10, 64)
		count, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil || count <= 0 {
			continue
		}
		out = append(out, idMapRange{inside, count})
	}
	return out
}

// idMapped reports whether id exists in the namespace. An unmapped UID makes
// the login fail in setresuid with "Invalid argument".
func idMapped(ranges []idMapRange, id int64) bool {
	for _, r := range ranges {
		if id >= r.inside && id < r.inside+r.count {
			return true
		}
	}
	return false
}

// idMapReport looks up the UID and primary GID of each distinct member via ids.
// checked counts the members whose IDs were read; outside lists those whose UID
// or GID is missing from uids/gids; unresolved lists those whose lookup failed,
// so their fit is unknown.
func idMapReport(members []string, ids func(string) (uid, gid int64, err error), uids, gids []idMapRange) (checked int, outside, unresolved []string) {
	seen := map[string]bool{}
	for _, m := range members {
		if seen[m] {
			continue
		}
		seen[m] = true
		uid, gid, err := ids(m)
		if err != nil {
			unresolved = append(unresolved, m)
			continue
		}
		checked++
		if !idMapped(uids, uid) || !idMapped(gids, gid) {
			outside = append(outside, fmt.Sprintf("%s (uid %d, gid %d)", m, uid, gid))
		}
	}
	return checked, outside, unresolved
}

// directoryUserIDs returns the UID and primary GID SSSD reports for user.
func directoryUserIDs(user string) (uid, gid int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "-s", "sss", "passwd", "--", user).Output()
	if err != nil {
		return 0, 0, err
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) < 4 {
		return 0, 0, fmt.Errorf("unexpected passwd entry for %s", user)
	}
	if uid, err = strconv.ParseInt(f[2], 10, 64); err != nil {
		return 0, 0, err
	}
	gid, err = strconv.ParseInt(f[3], 10, 64)
	return uid, gid, err
}
