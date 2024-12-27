// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certificate

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
	"github.com/cenkalti/backoff"
)

type certService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	idCfg   *config.IdentityConfig
	handler *identityHandler
	run     func() error
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	if ctx.Err() != nil {
		log.Info("Skipped certificate provider initiation")
		return nil, nil
	}

	// TODO: This log should be moved to derived-service-cert.go
	if !idCfg.ServiceCert.CopperArgos.Use {
		log.Infof("Certificate provisioning is disabled with empty options: provider service[%s]", idCfg.ServiceCert.CopperArgos.Provider)
	}

	// TODO: This log should be moved to derived-role-cert.go
	if !idCfg.RoleCert.Use {
		log.Infof("Role certificate provisioning is disabled with empty options: roles[%s], filename format[%s]", idCfg.RoleCert.TargetDomainRoles, idCfg.RoleCert.Format)
	}

	handler, err := InitIdentityHandler(idCfg)
	if err != nil {
		log.Errorf("Failed to initialize client for certificates: %s", err.Error())
		return nil, err
	}

	// identity & keyPEM will be STORED to the local file system:
	var keyPEM, k8sSecretBackupKeyPEM, forceInitKeyPEM []byte
	var identity, k8sSecretBackupIdentity, forceInitIdentity *InstanceIdentity

	// RoleCert Keys and Certs will be STORED to the local file system:
	var roleKeyPEM []byte
	var roleCerts [](*RoleCertificate)

	// identity & keyPEM that will NOT be STORED to the local file system:
	var localFileKeyPEM []byte
	var localFileIdentity *InstanceIdentity

	// Write files to local file system
	writeFiles := func() error {
		w := util.NewWriter()
		if identity != nil && localFileKeyPEM == nil && localFileIdentity == nil {
			leafPEM := []byte(identity.X509CertificatePEM)
			if len(leafPEM) != 0 && len(keyPEM) != 0 {
				x509Cert, err := util.CertificateFromPEMBytes(leafPEM)
				if err != nil {
					return fmt.Errorf("unable to parse x509 cert: %w", err)
				}
				log.Infof("[New Instance Certificate] Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, SerialNumber: %s, DNSNames: %s",
					x509Cert.Subject, x509Cert.Issuer, x509Cert.NotBefore, x509Cert.NotAfter, x509Cert.SerialNumber, x509Cert.DNSNames)
				log.Debugf("Saving x509 cert[%d bytes] at %s", len(leafPEM), idCfg.CertFile)
				if err := w.AddBytes(idCfg.CertFile, 0644, leafPEM); err != nil {
					return fmt.Errorf("unable to save x509 cert: %w", err)
				}
				log.Debugf("Saving x509 key[%d bytes] at %s", len(keyPEM), idCfg.KeyFile)
				if err := w.AddBytes(idCfg.KeyFile, 0644, keyPEM); err != nil {
					return fmt.Errorf("unable to save x509 key: %w", err)
				}
			}

			caCertPEM := []byte(identity.X509CACertificatePEM)
			if len(caCertPEM) != 0 && idCfg.CaCertFile != "" {
				log.Debugf("Saving x509 cacert[%d bytes] at %s", len(caCertPEM), idCfg.CaCertFile)
				if err := w.AddBytes(idCfg.CaCertFile, 0644, caCertPEM); err != nil {
					return fmt.Errorf("unable to save x509 cacert: %w", err)
				}
			}
		}

		if roleCerts != nil {
			for _, rolecert := range roleCerts {
				roleCertPEM := []byte(rolecert.X509Certificate)
				if len(roleCertPEM) != 0 {
					log.Infof("[New Role Certificate] Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, SerialNumber: %s, DNSNames: %s",
						rolecert.Subject, rolecert.Issuer, rolecert.NotBefore, rolecert.NotAfter, rolecert.SerialNumber, rolecert.DNSNames)

					outPath, err := extutil.GeneratePath(idCfg.RoleCert.Format, rolecert.Domain, rolecert.Role, idCfg.RoleCert.Delimiter)
					if err != nil {
						return fmt.Errorf("failed to generate path for role cert with format [%s], domain [%s], role [%s], delimiter [%s]: %w", idCfg.RoleCert.Format, rolecert.Domain, rolecert.Role, idCfg.RoleCert.Delimiter, err)
					}
					// Create the directory before saving role certificates
					if err := extutil.CreateDirectory(outPath); err != nil {
						return fmt.Errorf("unable to create directory for x509 role cert: %w", err)
					}
					log.Debugf("Saving x509 role cert[%d bytes] at [%s]", len(roleCertPEM), outPath)
					if err := w.AddBytes(outPath, 0644, roleCertPEM); err != nil {
						return fmt.Errorf("unable to save x509 role cert: %w", err)
					}

					if idCfg.RoleCert.KeyFormat != "" {
						outKeyPath, err := extutil.GeneratePath(idCfg.RoleCert.KeyFormat, rolecert.Domain, rolecert.Role, idCfg.RoleCert.Delimiter)
						if err != nil {
							return fmt.Errorf("failed to generate path for role cert key with format [%s], domain [%s], role [%s], delimiter [%s]: %w", idCfg.RoleCert.KeyFormat, rolecert.Domain, rolecert.Role, idCfg.RoleCert.Delimiter, err)
						}
						// Create the directory before saving role certificates keys
						if err := extutil.CreateDirectory(outKeyPath); err != nil {
							return fmt.Errorf("unable to create directory for x509 role cert: %w", err)
						}
						log.Debugf("Saving x509 role cert key[%d bytes] at [%s]", len(roleKeyPEM), outKeyPath)
						if err := w.AddBytes(outKeyPath, 0644, roleKeyPEM); err != nil {
							return fmt.Errorf("unable to save x509 role cert key: %w", err)
						}
					}
				}
			}
		}

		return w.Save()
	}

	identityProvisioningRequest := func(forceInit bool) (err error, identity *InstanceIdentity, keyPEM []byte) {
		log.Infof("Mapped Athenz domain[%s], service[%s]", handler.Domain(), handler.Service())

		identity, keyPEM, err = handler.GetX509Cert(forceInit)

		if err != nil {
			log.Warnf("Error while requesting x509 certificate to identity provider: %s", err.Error())

			if idCfg.K8sSecretBackup.UseWrite {
				log.Errorf("Failed to receive x509 certificate to update kubernetes secret[%s]: %s", idCfg.K8sSecretBackup.Secret, err.Error())
				return
			}

		} else {
			log.Info("Successfully received x509 certificate from identity provider")

			if idCfg.K8sSecretBackup.UseWrite {

				log.Infof("Attempting to save x509 certificate to kubernetes secret[%s]...", idCfg.K8sSecretBackup.Secret)

				err = handler.ApplyX509CertToSecret(identity, keyPEM)
				if err != nil {
					log.Errorf("Failed to save x509 certificate to kubernetes secret: %s", err.Error())
					return
				}

				log.Infof("Successfully saved x509 certificate to kubernetes secret")
			} else {
				log.Debugf("Skipping to save x509 certificate temporary backup to Kubernetes secret[%s]", idCfg.K8sSecretBackup.Secret)
			}
		}

		return
	}

	roleCertProvisioningRequest := func() (err error, roleCerts [](*RoleCertificate), roleKeyPEM []byte) {
		if !idCfg.RoleCert.Use {
			return nil, nil, nil
		}

		log.Infof("Attempting to get x509 role certs from identity provider: targets[%s]...", idCfg.RoleCert.TargetDomainRoles)

		roleCerts, roleKeyPEM, err = handler.GetX509RoleCert()
		if err != nil {
			log.Warnf("Error while requesting x509 role certificate to identity provider: %s", err.Error())
			return err, nil, nil
		}

		log.Info("Successfully received x509 role certs from identity provider")
		return nil, roleCerts, roleKeyPEM
	}

	run := func() error {
		if idCfg.ServiceCert.CopperArgos.Use {
			log.Infof("Attempting to request x509 certificate to identity provider[%s]...", idCfg.ServiceCert.CopperArgos.Provider)

			err, identity, keyPEM = identityProvisioningRequest(false)
			if err != nil {
				log.Errorf("Failed to retrieve x509 certificate from identity provider: %s", err.Error())
			}
			if identity != nil && len(keyPEM) != 0 {
				errUpdate := idCfg.Reloader.UpdateCertificate([]byte(identity.X509CertificatePEM), keyPEM)
				if errUpdate != nil {
					log.Errorf("Failed to update x509 certificate into certificate reloader: %s", errUpdate.Error())
				}
			}
		} else if idCfg.ServiceCert.LocalCert.Use {
			log.Debug("Attempting to load x509 certificate from cert reloader...")
			localFileKeyPEM, localFileCertPEM, err := idCfg.Reloader.GetLatestKeyAndCert()
			if err != nil {
				log.Warnf("Error while reading x509 certificate key from cert reloader: %s", err.Error())
				return err
			}
			localFileIdentity, err = InstanceIdentityFromPEMBytes(localFileCertPEM)
			if err != nil {
				log.Warnf("Error while parsing x509 certificate from cert reloader: %s", err.Error())
			}
			if localFileIdentity == nil || len(localFileKeyPEM) == 0 {
				log.Errorf("Failed to load x509 certificate from cert reloader to get x509 role certs: key size[%d]bytes, certificate size[%d]bytes", len(localFileCertPEM), len(localFileKeyPEM))
			} else {
				identity = localFileIdentity
				keyPEM = localFileKeyPEM
			}
		} else { // We are not immediately returning an error here, as there is a chance that the kubernetes secret backup is enabled:
			log.Debugf("Skipping to request/load x509 certificate: identity provider[%s], key[%s], cert[%s]", idCfg.ServiceCert.CopperArgos.Provider, idCfg.KeyFile, idCfg.CertFile)
		}

		if identity == nil || len(keyPEM) == 0 {
			if idCfg.K8sSecretBackup.UseRead {
				log.Infof("Attempting to load x509 certificate temporary backup from kubernetes secret[%s]...", idCfg.K8sSecretBackup.Secret)

				k8sSecretBackupIdentity, k8sSecretBackupKeyPEM, err = handler.GetX509CertFromSecret()
				if err != nil {
					log.Warnf("Error while loading x509 certificate temporary backup from kubernetes secret: %s", err.Error())
				}

				if k8sSecretBackupIdentity == nil || len(k8sSecretBackupKeyPEM) == 0 {
					log.Warnf("Failed to load x509 certificate temporary backup from kubernetes secret: secret was empty")
				} else {
					identity = k8sSecretBackupIdentity
					keyPEM = k8sSecretBackupKeyPEM
					log.Infof("Successfully loaded x509 certificate from kubernetes secret")
					if identity != nil && len(keyPEM) != 0 {
						errUpdate := idCfg.Reloader.UpdateCertificate([]byte(identity.X509CertificatePEM), keyPEM)
						if errUpdate != nil {
							log.Errorf("Failed to update x509 certificate into certificate reloader: %s", errUpdate.Error())
						}
					}
				}
			} else {
				log.Debugf("Skipping to load x509 certificate temporary backup from Kubernetes secret[%s]", idCfg.K8sSecretBackup.Secret)
			}
		}

		if identity == nil || len(keyPEM) == 0 {
			return fmt.Errorf("Failed to prepare x509 certificate")
		}

		if k8sSecretBackupIdentity != nil && len(k8sSecretBackupKeyPEM) != 0 && idCfg.ServiceCert.CopperArgos.Use {
			log.Infof("Attempting to request renewed x509 certificate to identity provider[%s]...", idCfg.ServiceCert.CopperArgos.Provider)
			err, forceInitIdentity, forceInitKeyPEM = identityProvisioningRequest(true)
			if err != nil {
				log.Warnf("Failed to retrieve renewed x509 certificate from identity provider: %s, continuing with the backup certificate from kubernetes secret", err.Error())
			} else {
				identity = forceInitIdentity
				keyPEM = forceInitKeyPEM

				if identity != nil && len(keyPEM) != 0 {
					errUpdate := idCfg.Reloader.UpdateCertificate([]byte(identity.X509CertificatePEM), keyPEM)
					if errUpdate != nil {
						log.Errorf("Failed to update x509 certificate into certificate reloader: %s", errUpdate.Error())
					}
				}
			}
		}

		err, roleCerts, roleKeyPEM = roleCertProvisioningRequest()
		if err != nil {
			return err
		}

		err = writeFiles()
		if err != nil {
			if forceInitIdentity != nil || forceInitKeyPEM != nil {
				log.Errorf("Failed to save files for renewed key[%s], renewed cert[%s] and renewed certificates for roles[%v]", idCfg.KeyFile, idCfg.CertFile, idCfg.RoleCert.TargetDomainRoles)
			} else {
				log.Errorf("Failed to save files for key[%s], cert[%s] and certificates for roles[%v]", idCfg.KeyFile, idCfg.CertFile, idCfg.RoleCert.TargetDomainRoles)
			}
		}

		return err
	}

	// initialize with retry
	ebo := newExponentialBackOff(ctx, config.DEFAULT_MAX_ELAPSED_TIME_ON_INIT)
	err = backoff.RetryNotify(run, ebo, func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to get initial certificates: %s. Retrying in %s", err.Error(), backoffDelay)
	})
	if err != nil {
		// mode=init, must output preset certificates
		if idCfg.Init {
			log.Errorf("Failed to get initial certificates after multiple retries for init mode: %s", err.Error())
			return nil, err
		}
		// mode=refresh, on retry error, ignore and continue server startup
		log.Errorf("Failed to get initial certificates after multiple retries for refresh mode: %s, will try to continue startup process...", err.Error())
	}

	return &certService{
		shutdownChan: make(chan struct{}, 1),
		idCfg:        idCfg,
		handler:      handler,
		run:          run,
	}, nil
}

// Start refreshes certificates periodically
func (cs *certService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped certificate provider start")
		return nil
	}

	if cs.idCfg.Refresh > 0 {
		t := time.NewTicker(cs.idCfg.Refresh)
		cs.shutdownWg.Add(1)
		go func() {
			defer t.Stop()
			defer cs.shutdownWg.Done()

			notifyOnErr := func(err error, backoffDelay time.Duration) {
				log.Errorf("Failed to refresh certificates: %s. Retrying in %s", err.Error(), backoffDelay)
			}
			for {
				log.Infof("Will refresh key[%s], cert[%s] and certificates for roles[%v] with provider[%s], backup[%s] and secret[%s] within %s", cs.idCfg.KeyFile, cs.idCfg.CertFile, cs.idCfg.RoleCert.TargetDomainRoles, cs.idCfg.ServiceCert.CopperArgos.Provider, cs.idCfg.K8sSecretBackup.Raw, cs.idCfg.K8sSecretBackup.Secret, cs.idCfg.Refresh)

				select {
				case <-cs.shutdownChan:
					log.Info("Stopped certificate provider daemon")
					return
				case <-t.C:
					// skip refresh if context is done but Shutdown() is not called
					if ctx.Err() != nil {
						log.Infof("Skipped to refresh key[%s], cert[%s] and certificates for roles[%v] with provider[%s], backup[%s] and secret[%s]", cs.idCfg.KeyFile, cs.idCfg.CertFile, cs.idCfg.RoleCert.TargetDomainRoles, cs.idCfg.ServiceCert.CopperArgos.Provider, cs.idCfg.K8sSecretBackup.Raw, cs.idCfg.K8sSecretBackup.Secret)
						continue
					}

					// backoff retry until REFRESH_INTERVAL / 4 OR context is done
					err := backoff.RetryNotify(cs.run, newExponentialBackOff(ctx, cs.idCfg.Refresh/4), notifyOnErr)
					if err != nil {
						log.Errorf("Failed to refresh certificates after multiple retries: %s", err.Error())
					}
				}
			}
		}()
	}

	return nil
}

func (cs *certService) Shutdown() {
	log.Info("Initiating shutdown of certificate provider daemon ...")
	close(cs.shutdownChan)

	// wait for graceful shutdown
	cs.shutdownWg.Wait()

	// delete x509 certificate record to prevent future refresh
	// P.S. Shutdown() will ONLY run on mode=refresh, no need to check for idCfg.Init
	if cs.idCfg.DeleteInstanceID && cs.handler.InstanceID() != "" {
		log.Info("Attempting to delete x509 certificate record from identity provider...")
		err := cs.handler.DeleteX509CertRecord()
		if err != nil {
			log.Warnf("Failed to delete x509 certificate Instance ID record: %s", err.Error())
		} else {
			log.Infof("Successfully deleted x509 certificate Instance ID record[%s]", cs.handler.InstanceID())
		}
	}
}

// newExponentialBackOff returns a backoff config with first retry delay of 5s. Allow cancel by context.
func newExponentialBackOff(ctx context.Context, maxElapsedTime time.Duration) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = maxElapsedTime

	return backoff.WithContext(b, ctx)
}
