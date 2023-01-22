package identity

import (
	"io/ioutil"
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
	var keyPem, certPem []byte

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

	run := func() error {

		if idConfig.ProviderService != "" {

			log.Infof("Attempting to create/refresh x509 certificate from identity provider[%s]...", idConfig.ProviderService)

			log.Infof("Mapped Athenz domain[%s], service[%s]", handler.Domain(), handler.Service())

			id, keyPem, err = handler.GetX509Cert()
			if err != nil {

				log.Warnf("Error while creating/refreshing x509 certificate from identity provider: %s", err.Error())

			} else {

				log.Infoln("Successfully created/refreshed x509 certificate from identity provider")

				if idConfig.CertSecret != "" && idConfig.Backup {

					log.Infof("Attempting to save x509 certificate to kubernetes secret[%s]...", idConfig.CertSecret)

					err = handler.ApplyX509CertToSecret(id, keyPem)
					if err != nil {
						log.Errorf("Error while saving x509 certificate to kubernetes secret: %s", err.Error())
						return err
					}

					log.Infof("Successfully saved x509 certificate to kubernetes secret")

				} else {

					log.Debugf("Skipping to save x509 certificate temporary backup to Kubernetes secret[%s]", idConfig.CertSecret)

				}
			}
		} else {

			log.Infof("No provider service specified. Skipping to create/refresh x509 certificate from identity provider...")

		}

		if id == nil || len(keyPem) == 0 {

			if idConfig.CertSecret != "" {

				log.Infof("Attempting to load x509 certificate temporary backup from kubernetes secret[%s]...", idConfig.CertSecret)

				id, keyPem, err = handler.GetX509CertFromSecret()
				if err != nil {
					log.Warnf("Error while loading x509 certificate temporary backup from kubernetes secret: %s", err.Error())
				}

				if id == nil || len(keyPem) == 0 {
					log.Warnf("Failed to load x509 certificate temporary backup from kubernetes secret: secret was empty")
				} else {

					log.Infof("Successfully loaded x509 certificate from kubernetes secret")

				}
			} else {

				log.Debugf("Skipping to load x509 certificate temporary backup from Kubernetes secret")

			}
		}

		var roleCerts [](*RoleCertificate)
		if idConfig.TargetDomainRoles != "" {

			if id == nil || len(keyPem) == 0 {

				log.Debugf("Attempting to load x509 certificate from local file to retrieve x509 role certs: key[%s], cert[%s]...", idConfig.KeyFile, idConfig.CertFile)

				certPem, err = ioutil.ReadFile(idConfig.CertFile)
				if err != nil {
					log.Warnf("Error while reading x509 certificate from local file[%s]: %s", idConfig.CertFile, err.Error())
				}
				keyPem, err = ioutil.ReadFile(idConfig.KeyFile)
				if err != nil {
					log.Warnf("Error while reading x509 certificate key from local file[%s]: %s", idConfig.KeyFile, err.Error())
				}

				id, err = InstanceIdentityFromPEMBytes(certPem)
				if err != nil {
					log.Warnf("Error while parsing x509 certificate from local file: %s", err.Error())
				}

				if id == nil || len(keyPem) == 0 {
					log.Errorf("Failed to load x509 certificate from local file to retrieve x509 role certs: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))
				} else {

					log.Debugf("Successfully loaded x509 certificate from local file to retrieve x509 role certs: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))

				}
			}

			log.Infof("Attempting to retrieve x509 role certs from identity provider: targets[%s]...", idConfig.TargetDomainRoles)

			roleCerts, err = handler.GetX509RoleCert(id, keyPem)
			if err != nil {
				err = errors.Wrap(err, "Failed to retrieve x509 role certs")
				log.Errorf("%s", err.Error())

				return err
			} else {
				log.Infoln("Successfully retrieved x509 role certs from identity provider")
			}
		} else {

			log.Debugf("Role certificate provisioning is disabled with empty target roles: roles[%s]", idConfig.TargetDomainRoles)

		}

		return writeFiles(id, keyPem, roleCerts)
	}

	deleteRequest := func() error {
		if idConfig.DeleteInstanceID {

			log.Infoln("Attempting to delete x509 certificate record from identity provider...")

			err := handler.DeleteX509CertRecord()
			if err != nil {
				log.Errorf("Error while deleting x509 certificate record: %s", err.Error())
				return err
			}

			log.Infof("Deleted Instance ID record[%s]", handler.InstanceID())

			log.Infoln("Successfully deleted x509 certificate record from identity provider")
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
			log.Errorf("Failed to retrieve initial certificate after multiple retries: %s", err.Error())
		}

		return err
	}

	go func() {
		t := time.NewTicker(idConfig.Refresh)
		defer t.Stop()

		for {

			log.Infof("Refreshing key[%s], cert[%s] and certificates for roles[%v] in %s", idConfig.KeyFile, idConfig.CertFile, idConfig.TargetDomainRoles, idConfig.Refresh)

			select {
			case <-t.C:
				err := backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh certificate after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				err := deleteRequest()
				if err != nil {
					log.Errorf("Failed to delete certificate record: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil
}
