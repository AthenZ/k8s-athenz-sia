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

package identity

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/token"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
)

func Certificated(idConfig *config.IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {

	if stopChan == nil {
		panic(fmt.Errorf("Certificated: stopChan cannot be empty"))
	}

	if idConfig.ProviderService == "" {
		log.Infof("Certificate provisioning is disabled with empty options: provider service[%s]", idConfig.ProviderService)
	}

	if idConfig.TargetDomainRoles == "" || idConfig.RoleCertDir == "" {
		log.Infof("Role certificate provisioning is disabled with empty options: roles[%s], output directory[%s]", idConfig.TargetDomainRoles, idConfig.RoleCertDir)
	}

	var identity, k8sSecretBackupIdentity, forceInitIdentity *InstanceIdentity
	var keyPEM, k8sSecretBackupKeyPEM, forceInitKeyPEM []byte

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Failed to initialize client for certificates: %s", err.Error())
		return err, nil
	}

	writeFiles := func(id *InstanceIdentity, keyPEM []byte, roleCerts [](*RoleCertificate), roleKeyPEM []byte) error {

		w := util.NewWriter()

		if id != nil {
			leafPEM := []byte(id.X509CertificatePEM)
			if len(leafPEM) != 0 && len(keyPEM) != 0 {
				x509Cert, err := util.CertificateFromPEMBytes(leafPEM)
				if err != nil {
					return errors.Wrap(err, "unable to parse x509 cert")
				}
				log.Infof("[New Instance Certificate] Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, SerialNumber: %s, DNSNames: %s",
					x509Cert.Subject, x509Cert.Issuer, x509Cert.NotBefore, x509Cert.NotAfter, x509Cert.SerialNumber, x509Cert.DNSNames)
				log.Debugf("Saving x509 cert[%d bytes] at %s", len(leafPEM), idConfig.CertFile)
				if err := w.AddBytes(idConfig.CertFile, 0644, leafPEM); err != nil {
					return errors.Wrap(err, "unable to save x509 cert")
				}
				log.Debugf("Saving x509 key[%d bytes] at %s", len(keyPEM), idConfig.KeyFile)
				if err := w.AddBytes(idConfig.KeyFile, 0644, keyPEM); err != nil { // TODO: finalize perms and user
					return errors.Wrap(err, "unable to save x509 key")
				}
			}

			caCertPEM := []byte(id.X509CACertificatePEM)
			if len(caCertPEM) != 0 && idConfig.CaCertFile != "" {
				log.Debugf("Saving x509 cacert[%d bytes] at %s", len(caCertPEM), idConfig.CaCertFile)
				if err := w.AddBytes(idConfig.CaCertFile, 0644, caCertPEM); err != nil {
					return errors.Wrap(err, "unable to save x509 cacert")
				}
			}
		}

		if roleCerts != nil {
			// Create the directory before saving role certificates
			if err := os.MkdirAll(idConfig.RoleCertDir, 0755); err != nil {
				return errors.Wrap(err, "unable to create directory for x509 role cert")
			}

			for _, rolecert := range roleCerts {
				roleCertPEM := []byte(rolecert.X509Certificate)
				if len(roleCertPEM) != 0 {
					log.Infof("[New Role Certificate] Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, SerialNumber: %s, DNSNames: %s",
						rolecert.Subject, rolecert.Issuer, rolecert.NotBefore, rolecert.NotAfter, rolecert.SerialNumber, rolecert.DNSNames)
					outPath := filepath.Join(idConfig.RoleCertDir, rolecert.Domain+idConfig.RoleCertFilenameDelimiter+rolecert.Role+".cert.pem")
					log.Debugf("Saving x509 role cert[%d bytes] at [%s]", len(roleCertPEM), outPath)
					if err := w.AddBytes(outPath, 0644, roleCertPEM); err != nil {
						return errors.Wrap(err, "unable to save x509 role cert")
					}

					if idConfig.RoleCertKeyFileOutput {
						outKeyPath := filepath.Join(idConfig.RoleCertDir, rolecert.Domain+idConfig.RoleCertFilenameDelimiter+rolecert.Role+".key.pem")
						log.Debugf("Saving x509 role cert key[%d bytes] at [%s]", len(roleKeyPEM), outKeyPath)
						if err := w.AddBytes(outKeyPath, 0644, roleKeyPEM); err != nil {
							return errors.Wrap(err, "unable to save x509 role cert key")
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

			if idConfig.CertSecret != "" && strings.Contains(idConfig.Backup, "write") {
				log.Errorf("Failed to receive x509 certificate to update kubernetes secret[%s]: %s", idConfig.CertSecret, err.Error())
				return
			}
		} else {
			log.Infoln("Successfully received x509 certificate from identity provider")

			if idConfig.CertSecret != "" && strings.Contains(idConfig.Backup, "write") {

				log.Infof("Attempting to save x509 certificate to kubernetes secret[%s]...", idConfig.CertSecret)

				err = handler.ApplyX509CertToSecret(identity, keyPEM)
				if err != nil {
					log.Errorf("Failed to save x509 certificate to kubernetes secret: %s", err.Error())
					return
				}

				log.Infof("Successfully saved x509 certificate to kubernetes secret")
			} else {
				log.Debugf("Skipping to save x509 certificate temporary backup to Kubernetes secret[%s]", idConfig.CertSecret)
			}
		}

		return
	}

	roleCertProvisioningRequest := func() (err error, roleCerts [](*RoleCertificate), roleKeyPEM []byte) {
		var roleIdentity *InstanceIdentity

		if idConfig.TargetDomainRoles == "" || idConfig.RoleCertDir == "" {
			return nil, nil, nil
		}

		roleIdentity = identity
		roleKeyPEM = keyPEM

		if roleIdentity == nil || len(roleKeyPEM) == 0 {
			return nil, nil, nil
		}

		log.Infof("Attempting to get x509 role certs from identity provider: targets[%s]...", idConfig.TargetDomainRoles)

		roleCerts, err = handler.GetX509RoleCert(roleIdentity, roleKeyPEM)
		if err != nil {
			log.Warnf("Error while requesting x509 role certificate to identity provider: %s", err.Error())
			return err, nil, nil
		}

		log.Infoln("Successfully received x509 role certs from identity provider")
		return nil, roleCerts, roleKeyPEM
	}

	// getExponentialBackoff will return a backoff config with first retry delay of 5s, and backoff retry
	// until REFRESH_INTERVAL / 4
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = idConfig.Refresh / 4
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh certificates: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	run := func() error {
		if idConfig.ProviderService != "" {
			log.Infof("Attempting to request x509 certificate to identity provider[%s]...", idConfig.ProviderService)

			err, identity, keyPEM = identityProvisioningRequest(false)
			if err != nil {
				log.Errorf("Failed to retrieve x509 certificate from identity provider: %s", err.Error())
			}
		} else if idConfig.KeyFile != "" && idConfig.CertFile != "" {
			log.Debugf("Attempting to load x509 certificate from local file: key[%s], cert[%s]...", idConfig.KeyFile, idConfig.CertFile)

			fileBackupCertPEM, err := ioutil.ReadFile(idConfig.CertFile)
			if err != nil {
				log.Warnf("Error while reading x509 certificate from local file[%s]: %s", idConfig.CertFile, err.Error())
			}
			fileBackupKeyPEM, err := ioutil.ReadFile(idConfig.KeyFile)
			if err != nil {
				log.Warnf("Error while reading x509 certificate key from local file[%s]: %s", idConfig.KeyFile, err.Error())
			}

			fileBackupIdentity, err := InstanceIdentityFromPEMBytes(fileBackupCertPEM)
			if err != nil {
				log.Warnf("Error while parsing x509 certificate from local file: %s", err.Error())
			}

			if fileBackupIdentity == nil || len(fileBackupKeyPEM) == 0 {
				log.Errorf("Failed to load x509 certificate from local file to get x509 role certs: key size[%d]bytes, certificate size[%d]bytes", len(fileBackupCertPEM), len(fileBackupKeyPEM))
			} else {
				identity = fileBackupIdentity
				keyPEM = fileBackupKeyPEM
				log.Debugf("Successfully loaded x509 certificate from local file to get x509 role certs: key size[%d]bytes, certificate size[%d]bytes", len(fileBackupCertPEM), len(fileBackupKeyPEM))
			}
		}

		if identity == nil || len(keyPEM) == 0 {
			if idConfig.CertSecret != "" && strings.Contains(idConfig.Backup, "read") {
				log.Infof("Attempting to load x509 certificate temporary backup from kubernetes secret[%s]...", idConfig.CertSecret)

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
				}
			} else {
				log.Debugf("Skipping to load x509 certificate temporary backup from Kubernetes secret[%s]", idConfig.CertSecret)
			}
		}

		if identity == nil || len(keyPEM) == 0 {
			return errors.New("Failed to prepare x509 certificate")
		}

		if k8sSecretBackupIdentity != nil && len(k8sSecretBackupKeyPEM) != 0 && idConfig.ProviderService != "" {
			log.Infof("Attempting to request renewed x509 certificate to identity provider[%s]...", idConfig.ProviderService)
			err, forceInitIdentity, forceInitKeyPEM = identityProvisioningRequest(true)
			if err != nil {
				log.Errorf("Failed to retrieve renewed x509 certificate from identity provider: %s", err.Error())
			} else {
				identity = forceInitIdentity
				keyPEM = forceInitKeyPEM
			}
		}

		err, roleCerts, roleKeyPEM := roleCertProvisioningRequest()
		if err != nil {
			return err
		}

		err = writeFiles(identity, keyPEM, roleCerts, roleKeyPEM)
		if err != nil {
			if forceInitIdentity != nil || forceInitKeyPEM != nil {
				log.Errorf("Failed to save files for renewed key[%s], renewed cert[%s] and renewed certificates for roles[%v]", idConfig.KeyFile, idConfig.CertFile, idConfig.TargetDomainRoles)
			} else {
				log.Errorf("Failed to save files for key[%s], cert[%s] and certificates for roles[%v]", idConfig.KeyFile, idConfig.CertFile, idConfig.TargetDomainRoles)
			}
		}

		return err
	}

	deleteRequest := func() error {
		if idConfig.DeleteInstanceID && !idConfig.Init && handler.InstanceID() != "" {

			log.Infoln("Attempting to delete x509 certificate record from identity provider...")

			err := handler.DeleteX509CertRecord()
			if err != nil {
				log.Warnf("Error while deleting x509 certificate Instance ID record: %s", err.Error())
				return err
			}

			log.Infof("Successfully deleted x509 certificate Instance ID record[%s]", handler.InstanceID())
		}

		return nil
	}

	if idConfig.DelayJitterSeconds != 0 {
		rand.Seed(time.Now().UnixNano())
		sleep := time.Duration(rand.Int63n(idConfig.DelayJitterSeconds)) * time.Second
		log.Infof("Delaying boot with jitter [%s] randomized from [%s]...", sleep, time.Duration(idConfig.DelayJitterSeconds)*time.Second)
		time.Sleep(sleep)
	}

	err = backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)

	if idConfig.Init {
		if err != nil {
			log.Errorf("Failed to get initial certificate after multiple retries: %s", err.Error())
			return err, nil
		}
	}

	tokenChan := make(chan struct{}, 1)
	err, tokenSdChan := token.Tokend(idConfig, tokenChan)
	if err != nil {
		log.Errorf("Error starting token provider[%s]", err)
		close(tokenChan)
		return err, nil
	}

	metricsChan := make(chan struct{}, 1)
	err, metricsSdChan := Metricsd(idConfig, metricsChan)
	if err != nil {
		log.Errorf("Error starting metrics exporter[%s]", err)
		close(metricsChan)
		close(tokenChan)
		return err, nil
	}

	healthcheckChan := make(chan struct{}, 1)
	err, healthcheckSdChan := Healthcheckd(idConfig, healthcheckChan)
	if err != nil {
		log.Errorf("Error starting health check server[%s]", err)
		close(healthcheckChan)
		close(metricsChan)
		close(tokenChan)
		return err, nil
	}

	shutdownChan := make(chan struct{}, 1)
	t := time.NewTicker(idConfig.Refresh)
	go func() {
		defer t.Stop()
		defer close(shutdownChan)

		for {

			log.Infof("Refreshing key[%s], cert[%s] and certificates for roles[%v] with provider[%s], backup[%s] and secret[%s] in %s", idConfig.KeyFile, idConfig.CertFile, idConfig.TargetDomainRoles, idConfig.ProviderService, idConfig.Backup, idConfig.CertSecret, idConfig.Refresh)

			select {
			case <-t.C:
				err := backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh x509 certificate after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				log.Info("Initiating shutdown of certificate provider daemon ...")
				err = deleteRequest()
				if err != nil {
					log.Errorf("Failed to delete x509 certificate Instance ID record: %s", err.Error())
				}
				close(healthcheckChan)
				close(metricsChan)
				close(tokenChan)
				if tokenSdChan != nil {
					<-tokenSdChan
				}
				if metricsSdChan != nil {
					<-metricsSdChan
				}
				if healthcheckSdChan != nil {
					<-healthcheckSdChan
				}
				return
			}
		}
	}()

	return nil, shutdownChan
}
