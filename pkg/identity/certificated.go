package identity

import (
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

func Certificated(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	if idConfig.ProviderService == "" {
		log.Infof("Certificate provisioning is disabled with empty options: provider service[%s]", idConfig.ProviderService)
	}

	if idConfig.TargetDomainRoles == "" || idConfig.RoleCertDir == "" {
		log.Infof("Role certificate provisioning is disabled with empty options: roles[%s], output directory[%s]", idConfig.TargetDomainRoles, idConfig.RoleCertDir)
	}

	var identity, backupIdentity *InstanceIdentity
	var keyPem, backupKeyPem, certPem []byte

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Failed to initialize client for certificates: %s", err.Error())
		return err
	}

	writeFiles := func(id *InstanceIdentity, keyPEM []byte, roleCerts [](*RoleCertificate)) error {

		if id == nil {
			return nil
		}

		w := util.NewWriter()

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

		if roleCerts != nil {
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
				}
			}
		}

		return w.Save()
	}

	identityProvisioningRequest := func(idConfig *IdentityConfig, handler *identityHandler, forceInit bool) (err error, identity *InstanceIdentity, keyPem []byte) {
		log.Infof("Attempting to request x509 certificate to identity provider[%s]...", idConfig.ProviderService)

		log.Infof("Mapped Athenz domain[%s], service[%s]", handler.Domain(), handler.Service())

		identity, keyPem, err = handler.GetX509Cert(forceInit)

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

				err = handler.ApplyX509CertToSecret(identity, keyPem)
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
			err, identity, keyPem = identityProvisioningRequest(idConfig, handler, false)
		}

		if identity == nil || len(keyPem) == 0 {
			if idConfig.CertSecret != "" && strings.Contains(idConfig.Backup, "read") {
				log.Infof("Attempting to load x509 certificate temporary backup from kubernetes secret[%s]...", idConfig.CertSecret)

				backupIdentity, backupKeyPem, err = handler.GetX509CertFromSecret()
				if err != nil {
					log.Warnf("Error while loading x509 certificate temporary backup from kubernetes secret: %s", err.Error())
				}

				if backupIdentity == nil || len(backupKeyPem) == 0 {
					log.Warnf("Failed to load x509 certificate temporary backup from kubernetes secret: secret was empty")
				} else {
					identity = backupIdentity
					keyPem = backupKeyPem
					log.Infof("Successfully loaded x509 certificate from kubernetes secret")
				}
			} else {

				log.Debugf("Skipping to load x509 certificate temporary backup from Kubernetes secret[%s]", idConfig.CertSecret)
			}
		}

		var roleCerts [](*RoleCertificate)
		if idConfig.TargetDomainRoles != "" && idConfig.RoleCertDir != "" {
			if identity == nil || len(keyPem) == 0 {
				log.Debugf("Attempting to load x509 certificate from local file to get x509 role certs: key[%s], cert[%s]...", idConfig.KeyFile, idConfig.CertFile)

				certPem, err = ioutil.ReadFile(idConfig.CertFile)
				if err != nil {
					log.Warnf("Error while reading x509 certificate from local file[%s]: %s", idConfig.CertFile, err.Error())
				}
				keyPem, err = ioutil.ReadFile(idConfig.KeyFile)
				if err != nil {
					log.Warnf("Error while reading x509 certificate key from local file[%s]: %s", idConfig.KeyFile, err.Error())
				}

				identity, err = InstanceIdentityFromPEMBytes(certPem)
				if err != nil {
					log.Warnf("Error while parsing x509 certificate from local file: %s", err.Error())
				}

				if identity == nil || len(keyPem) == 0 {
					log.Errorf("Failed to load x509 certificate from local file to get x509 role certs: key size[%d bytes], certificate size[%d bytes]", len(keyPem), len(certPem))
				} else {
					log.Debugf("Successfully loaded x509 certificate from local file to get x509 role certs: key size[%d bytes], certificate size[%d bytes]", len(keyPem), len(certPem))
				}
			}

			if identity != nil && len(keyPem) != 0 {
				log.Infof("Attempting to get x509 role certs from identity provider: targets[%s]...", idConfig.TargetDomainRoles)

				roleCerts, err = handler.GetX509RoleCert(identity, keyPem)
				if err != nil {
					log.Warnf("Error while requesting x509 role certificate to identity provider: %s", err.Error())
					return err
				} else {
					log.Infoln("Successfully received x509 role certs from identity provider")
				}
			}
		}

		err = writeFiles(identity, keyPem, roleCerts)
		if err != nil {
			log.Errorf("Failed to save files for key[%s], cert[%s] and certificates for roles[%v]", idConfig.KeyFile, idConfig.CertFile, idConfig.TargetDomainRoles)
			return err
		}

		if backupIdentity != nil && len(backupKeyPem) != 0 && idConfig.ProviderService != "" {
			err, identity, keyPem = identityProvisioningRequest(idConfig, handler, true)
		}

		return writeFiles(identity, keyPem, roleCerts)
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
			return err
		}
	}

	go func() {

		tokenChan := make(chan struct{})
		metricsChan := make(chan struct{})
		err = Tokend(idConfig, tokenChan)
		if err != nil {
			log.Errorf("Error starting token provider[%s]", err)
			return
		}
		err = Metricsd(idConfig, metricsChan)
		if err != nil {
			log.Errorf("Error starting metrics exporter[%s]", err)
			return
		}

		t := time.NewTicker(idConfig.Refresh)
		defer t.Stop()

		for {

			log.Infof("Refreshing key[%s], cert[%s] and certificates for roles[%v] with provider[%s], backup[%s] and secret[%s] in %s", idConfig.KeyFile, idConfig.CertFile, idConfig.TargetDomainRoles, idConfig.ProviderService, idConfig.Backup, idConfig.CertSecret, idConfig.Refresh)

			select {
			case <-t.C:
				err := backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh x509 certificate after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				err = deleteRequest()
				if err != nil {
					log.Errorf("Failed to delete x509 certificate Instance ID record: %s", err.Error())
				}
				close(metricsChan)
				close(tokenChan)
				return
			}
		}
	}()

	return nil
}
