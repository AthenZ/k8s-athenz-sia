package identity

import (
	"math/rand"
	"path/filepath"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

func Certificated(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	var id *InstanceIdentity
	var keyPem []byte

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Error while initializing handler: %s", err.Error())
		return err
	}

	writeFiles := func(id *InstanceIdentity, keyPEM []byte, roleCerts [](*RoleCertificate)) error {

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
		if len(caCertPEM) != 0 {
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
					outPath := filepath.Join(idConfig.RoleCertDir, rolecert.Domain+":role."+rolecert.Role+".cert.pem")
					log.Debugf("Saving x509 role cert[%d bytes] at %s", len(roleCertPEM), outPath)
					if err := w.AddBytes(outPath, 0644, roleCertPEM); err != nil {
						return errors.Wrap(err, "unable to save x509 role cert")
					}
					outPath = filepath.Join(idConfig.RoleCertDir, rolecert.Domain+"_role."+rolecert.Role+".cert.pem")
					log.Debugf("Saving x509 role cert[%d bytes] at %s", len(roleCertPEM), outPath)
					if err := w.AddBytes(outPath, 0644, roleCertPEM); err != nil {
						return errors.Wrap(err, "unable to save x509 role cert")
					}
				}
			}
		}

		return w.Save()
	}

	// getExponentialBackoff will return a backoff config with first retry delay of 5s, and backoff retry
	// until params.refresh / 4
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = idConfig.Refresh / 4
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to create/refresh cert: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	postRequest := func() error {

		if !idConfig.SkipIdentityProvisioning {

			log.Infof("Mapped Athenz domain[%s], service[%s]", handler.Domain(), handler.Service())

			log.Infoln("Attempting to create/refresh x509 cert from identity provider...")
			id, keyPem, err = handler.GetX509Cert()

			if err != nil {

				log.Errorf("Error while creating/refreshing x509 cert from identity provider: %s", err.Error())
			} else {

				log.Infoln("Successfully created/refreshed x509 cert from identity provider")
			}
		} else {

			log.Infof("Skipping to create/refresh x509 cert from identity provider...")

			var certPEM []byte

			keyPem, certPEM, err = idConfig.Reloader.GetLatestKeyAndCert()
			if err != nil {
				log.Errorf("Error while reading x509 cert from local file: %s", err.Error())
			}

			id, err = InstanceIdentityFromPEMBytes(certPEM)
			if err != nil {
				log.Errorf("Error while parsing x509 cert from local file: %s", err.Error())
			}
		}

		if id == nil || len(keyPem) == 0 {

			if idConfig.CertSecret != "" && !idConfig.Backup {
				log.Warnf("Attempting to load x509 cert temporary backup from kubernetes secret[%s]...", idConfig.CertSecret)

				id, keyPem, err = handler.GetX509CertFromSecret()
				if err != nil {
					log.Errorf("Error while loading x509 cert temporary backup from kubernetes secret[%s]: %s", idConfig.CertSecret, err.Error())
					return err
				}

				if id == nil || len(keyPem) == 0 {
					log.Errorf("Failed to load x509 cert temporary backup from kubernetes secret[%s]: secret was empty", idConfig.CertSecret)
					return nil
				} else {

					log.Infof("Successfully loaded x509 cert from kubernetes secret[%s]", idConfig.CertSecret)

				}
			} else {

				log.Errorf("Failed to load x509 cert temporary backup from kubernetes secret[%s]: secret was not specified", idConfig.CertSecret)
				return nil
			}
		} else {

			if idConfig.CertSecret != "" && idConfig.Backup {

				log.Infof("Attempting to save x509 cert to kubernetes secret[%s]...", idConfig.CertSecret)

				err = handler.ApplyX509CertToSecret(id, keyPem)
				if err != nil {
					log.Errorf("Error while saving x509 cert to kubernetes secret[%s]: %s", idConfig.CertSecret, err.Error())
					return err
				}

				log.Infof("Successfully saved x509 cert to kubernetes secret[%s]", idConfig.CertSecret)

			} else {

				return nil
			}
		}

		var roleCerts [](*RoleCertificate)
		if idConfig.TargetDomainRoles != "" {
			log.Infoln("Attempting to retrieve x509 role certs from identity provider...")

			roleCerts, err = handler.GetX509RoleCert(id, keyPem)
			if err != nil {
				log.Errorf("Error while retrieving x509 role certs: %s", err.Error())
			} else {
				log.Infoln("Successfully retrieved x509 role certs from identity provider")
			}
		}

		return writeFiles(id, keyPem, roleCerts)
	}

	deleteRequest := func() error {
		if idConfig.DeleteInstanceID {
			log.Infoln("Attempting to delete x509 cert record from identity provider...")

			err := handler.DeleteX509CertRecord()
			if err != nil {
				log.Errorf("Error while deleting x509 cert record: %s", err.Error())
				return err
			}

			log.Infof("Deleted Instance ID record[%s]", handler.InstanceID())

			log.Infoln("Successfully deleted x509 cert record from identity provider")
		}

		return nil
	}

	if idConfig.DelayJitterSeconds != 0 {
		rand.Seed(time.Now().UnixNano())
		sleep := time.Duration(rand.Int63n(idConfig.DelayJitterSeconds)) * time.Second
		log.Infof("Delaying boot with jitter [%s] randomized from [%s]...", sleep, time.Duration(idConfig.DelayJitterSeconds)*time.Second)
		time.Sleep(sleep)
	}

	if idConfig.Init {
		return backoff.RetryNotify(postRequest, getExponentialBackoff(), notifyOnErr)
	}

	go func() {
		t := time.NewTicker(idConfig.Refresh)
		defer t.Stop()

		for {
			log.Infof("Refreshing cert[%s] roles[%v] in %s", idConfig.CertFile, idConfig.TargetDomainRoles, idConfig.Refresh)
			select {
			case <-t.C:
				err := backoff.RetryNotify(postRequest, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh cert after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				err := deleteRequest()
				if err != nil {
					log.Errorf("Failed to delete cert record: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil
}
