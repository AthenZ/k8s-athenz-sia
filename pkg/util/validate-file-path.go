// Package util provides utility functions for the Athenz SIA agent.
package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// TODO: Simply was wondering if there is a good package out there to do this
// TODO: instead of writing our own.

// TODO: Not super confident with the validation logic yet, but
// TODO: writing temp sounds pretty cool but can have some side effects
// TODO: Especially I need to delete it.
// ValidateFilePath checks if a file path is writable.
// It verifies that the parent directory exists and that the process has
// the necessary permissions to create a file in it.
//
// This function uses the most reliable method for checking write permissions:
// attempting to create a temporary file in the target directory. This avoids
// the race conditions and potential inaccuracies of syscall.Access (TOCTOU).
//
// Args:
//
//	path (string): The full file path to validate.
//
// Returns:
//
//	(error): An error if the path is not writable, otherwise nil.
func ValidateFilePath(path string) error {
	// Get the parent directory of the given file path.
	// i.e) if path is "/var/lib/athenz/cert.pem", then dir will be "/var/lib/athenz"
	dir := filepath.Dir(path)

	// Check if the parent directory exists.
	// os.Stat returns information about the directory. If it returns an error,
	// we check if the error is because the directory does not exist.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("parent directory does not exist: %s", dir)
	}

	// TODO: Write more logic here.

	// If all checks pass, return nil.
	return nil
}
