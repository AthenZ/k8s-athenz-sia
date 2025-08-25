package config

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func validFilePath(file_path string) error {
	dir_path := filepath.Dir(file_path)
	var target_path string
	_, file_err := os.Stat(file_path)
	_, dir_err := os.Stat(dir_path)

	if file_err == nil {
		// validate file path
		target_path = file_path
	} else if os.IsNotExist(file_err) && dir_err == nil {
		// validate dir path
		target_path = dir_path
	} else {
		return fmt.Errorf("file path not exist: %w, %w", file_err, dir_err)
	}

	err := unix.Access(target_path, unix.W_OK)
	if err != nil {
		return fmt.Errorf("file permission error: %w", err)
	}

	return nil
}

// Verify that the certificate file paths are in writable locations
func (idCfg *IdentityConfig) ValidateCertFilePath() error {
	// When idCfg.ServiceCert.LocalCert.Use is true, skip file writing and return early
	if idCfg.ServiceCert.LocalCert.Use {
		return nil
	}

	for _, certFile := range idCfg.ServiceCert.CopperArgos.Cert.Paths {
		err := validFilePath(certFile)
		if err != nil {
			return err
		}
	}
	for _, keyFile := range idCfg.ServiceCert.CopperArgos.Key.Paths {
		err := validFilePath(keyFile)
		if err != nil {
			return err
		}
	}
	return validFilePath(idCfg.CaCertFile)
}
