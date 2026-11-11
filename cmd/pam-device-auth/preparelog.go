package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

// lookupGroup resolves a group name; a variable so tests need no group
// database.
var lookupGroup = user.LookupGroup

// logGroupID returns the gid of the group that may read the log (adm), or -1
// on a host that has no such group. Every other lookup failure is an error.
func logGroupID() (int, error) {
	g, err := lookupGroup("adm")
	var unknown user.UnknownGroupError
	switch {
	case errors.As(err, &unknown):
		return -1, nil
	case err != nil:
		return 0, fmt.Errorf("look up group adm: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group adm has the gid %q: %w", g.Gid, err)
	}
	return gid, nil
}

// runPrepareLog is --prepare-log, run by the package's post-install script:
// it creates the log file or checks the existing one (a regular file, no mode
// bits beyond 0640) and gives it to root and the group adm. It works on the
// open file; the script's former touch, chmod and chown followed a symlink at
// the path.
func runPrepareLog() int {
	gid, err := logGroupID()
	if err == nil {
		err = logger.PrepareLog(logFile, gid)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", logFile, err)
		return 1
	}
	return 0
}
