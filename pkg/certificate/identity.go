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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/k8s"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

// RoleCertificate stores role certificate
type RoleCertificate struct {
	Domain          string
	Role            string
	Subject         pkix.Name
	Issuer          pkix.Name
	NotBefore       time.Time
	NotAfter        time.Time
	SerialNumber    *big.Int
	DNSNames        []string
	X509Certificate string
}

// InstanceIdentity stores instance identity certificate
type InstanceIdentity struct {
	X509CertificatePEM   string
	X509CACertificatePEM string
}

type identityHandler struct {
	idCfg        *config.IdentityConfig
	client       zts.ZTSClient
	domain       string
	service      string
	instanceID   string
	csrOptions   *util.CSROptions
	secretClient *k8s.SecretsClient
}

// InitIdentityHandler initializes the ZTS client and parses the config to create CSR options
func InitIdentityHandler(idCfg *config.IdentityConfig) (*identityHandler, error) {

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if !idCfg.Init {
		tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return idCfg.Reloader.GetLatestCertificate()
		}
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tlsConfig

	if idCfg.ServerCACert != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(idCfg.ServerCACert)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = certPool
		t.TLSClientConfig = tlsConfig
	}

	client := zts.NewClient(idCfg.Endpoint, t)
	// Add User-Agent header to ZTS client for fetching x509 certificate
	client.AddCredentials("User-Agent", config.USER_AGENT)

	csrOptions, err := PrepareIdentityCsrOptions(idCfg, idCfg.ServiceCert.CopperArgos.AthenzDomainName, idCfg.ServiceCert.CopperArgos.AthenzServiceName)
	if err != nil {
		return nil, err
	}

	var secretClient *k8s.SecretsClient
	if idCfg.K8sSecretBackup.Use {
		secretClient, err = k8s.NewSecretClient(idCfg.K8sSecretBackup.Secret, idCfg.Namespace)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize kubernetes secret client, err: %v", err)
		}
	}

	return &identityHandler{
		idCfg:        idCfg,
		client:       client,
		domain:       idCfg.ServiceCert.CopperArgos.AthenzDomainName,
		service:      idCfg.ServiceCert.CopperArgos.AthenzServiceName,
		instanceID:   idCfg.PodUID,
		csrOptions:   csrOptions,
		secretClient: secretClient,
	}, nil
}

// GetX509CertFromSecret loads X.509 certificate from Kubernetes Secret
func (h *identityHandler) GetX509CertFromSecret() (*InstanceIdentity, []byte, error) {
	if h.secretClient != nil {
		secret, isNotFound, err := h.secretClient.GetIdentitySecret()
		if err != nil && !isNotFound {
			return nil, nil, fmt.Errorf("Failed to get identity from kubernetes secret, err: %v", err)
		}

		if secret != nil {
			keyPEM, certPEM := k8s.GetKeyAndCertificateFromSecret(secret)
			identity, err := InstanceIdentityFromPEMBytes(certPEM)

			return identity, keyPEM, err
		}
	}

	return nil, nil, nil
}

// ApplyX509CertToSecret saves X.509 certificate to Kubernetes Secret
func (h *identityHandler) ApplyX509CertToSecret(identity *InstanceIdentity, keyPEM []byte) error {
	if h.secretClient != nil {
		_, err := h.secretClient.ApplyIdentitySecret(keyPEM, []byte(identity.X509CertificatePEM))
		if err != nil {
			return fmt.Errorf("Failed to backup identity to kubernetes secret, err: %v", err)
		}
	}

	return nil
}

// GetX509Cert makes ZTS API calls to generate an X.509 certificate
func (h *identityHandler) GetX509Cert(forceInit bool) (*InstanceIdentity, []byte, error) {

	if h.csrOptions == nil {
		return nil, nil, nil
	}

	keyPEM, csrPEM, err := util.GenerateKeyAndCSR(*h.csrOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate key and csr, err: %v", err)
	}

	saToken, err := os.ReadFile(h.idCfg.SaTokenFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read service account token file, err: %v", err)
	}

	var id *zts.InstanceIdentity
	if h.idCfg.Init || forceInit {
		id, _, err = h.client.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
			Provider:        zts.ServiceName(h.idCfg.ServiceCert.CopperArgos.Provider),
			Domain:          zts.DomainName(h.domain),
			Service:         zts.SimpleName(h.service),
			AttestationData: string(saToken),
			Csr:             string(csrPEM),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to call PostInstanceRegisterInformation, err: %v", err)
		}

	} else {
		id, err = h.client.PostInstanceRefreshInformation(
			zts.ServiceName(h.idCfg.ServiceCert.CopperArgos.Provider),
			zts.DomainName(h.domain),
			zts.SimpleName(h.service),
			zts.PathElement(h.idCfg.PodUID),
			&zts.InstanceRefreshInformation{
				AttestationData: string(saToken),
				Csr:             string(csrPEM),
			})
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to call PostInstanceRefreshInformation, err: %v", err)
		}
	}

	identity := &InstanceIdentity{
		X509CertificatePEM:   id.X509Certificate + id.X509CertificateSigner,
		X509CACertificatePEM: id.X509CertificateSigner,
	}

	return identity, keyPEM, err
}

// GetX509RoleCert makes ZTS API calls to generate an X.509 role certificate
func (h *identityHandler) GetX509RoleCert() (rolecerts [](*RoleCertificate), roleKeyPEM []byte, err error) {

	keyPEM, certPEM, err := h.idCfg.Reloader.GetLatestKeyAndCert()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to load tls client key pair from cert reloader for PostRoleCertificateRequest, err: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to load tls client key pair for PostRoleCertificateRequest, err: %v", err)
	}

	x509LeafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse identity certificate from cert reloader for PostRoleCertificateRequest, err: %v", err)
	}
	domain, service, err := extractServiceDetailsFromCert(x509LeafCert)
	if err != nil {
		return nil, nil, err
	}

	roleCsrOptions, err := PrepareRoleCsrOptions(h.idCfg, domain, service)
	if err != nil || roleCsrOptions == nil {
		return nil, nil, err
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	t.TLSClientConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &cert, nil
	}

	if h.idCfg.ServerCACert != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(h.idCfg.ServerCACert)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to load tls client ca certificate for PostRoleCertificateRequest, err: %v", err)
		}
		certPool.AppendCertsFromPEM(caCert)
		t.TLSClientConfig.RootCAs = certPool
	}

	// TODO: no need to renew ZTS Client after https://github.com/AthenZ/k8s-athenz-sia/pull/99
	// In init mode, the existing ZTS Client does not have client certificate set.
	// When config.Reloader.GetLatestCertificate() is called to load client certificate, the first certificate has not written to the file yet.
	// Therefore, ZTS Client must be renewed to make sure the ZTS Client loads the latest client certificate.
	//
	// The intermediate certificates may be different between each ZTS.
	// Therefore, ZTS Client for PostRoleCertificateRequest must share the same endpoint as PostInstanceRegisterInformation/PostInstanceRefreshInformation
	roleCertClient := zts.NewClient(h.idCfg.Endpoint, t)
	// Add User-Agent header to ZTS client for fetching x509 role certificates
	roleCertClient.AddCredentials("User-Agent", config.USER_AGENT)

	key, err := PrivateKeyFromPEMBytes(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to prepare csr, failed to read private key pem bytes for PostRoleCertificateRequest, err: %v", err)
	}

	var intermediateCerts string
	if h.idCfg.IntermediateCertBundle != "" {
		intermediateCertBundle, err := roleCertClient.GetCertificateAuthorityBundle(zts.SimpleName(h.idCfg.IntermediateCertBundle))
		if err != nil || intermediateCertBundle == nil || intermediateCertBundle.Certs == "" {
			return nil, nil, fmt.Errorf("GetCertificateAuthorityBundle failed for role certificate, err: %v", err)
		}
		intermediateCerts = intermediateCertBundle.Certs
	}

	for _, csrOption := range *roleCsrOptions {
		dr := strings.Split(csrOption.Subject.CommonName, ":role.")
		roleCsrPEM, err := util.GenerateCSR(key, csrOption)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to prepare csr, failed to generate csr for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
		}
		x509LeafCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to prepare csr, failed to parse certificate for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
		}
		roleRequest := &zts.RoleCertificateRequest{
			Csr:        string(roleCsrPEM),
			ExpiryTime: int64(x509LeafCert.NotAfter.Sub(time.Now()).Minutes()) + int64(config.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES), // Extract NotAfter from the instance certificate
		}

		roleCert, err := roleCertClient.PostRoleCertificateRequestExt(roleRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("PostRoleCertificateRequest failed for principal[%s.%s] to get Role Subject CommonName[%s], err: %v", domain, service, csrOption.Subject.CommonName, err)
		}
		x509RoleCert, err := util.CertificateFromPEMBytes([]byte(roleCert.X509Certificate))
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to parse x509 certificate for PostRoleCertificateRequest response, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
		}
		rolecerts = append(rolecerts, &RoleCertificate{
			Domain:          dr[0],
			Role:            dr[1],
			Subject:         x509RoleCert.Subject,
			Issuer:          x509RoleCert.Issuer,
			NotBefore:       x509RoleCert.NotBefore,
			NotAfter:        x509RoleCert.NotAfter,
			SerialNumber:    x509RoleCert.SerialNumber,
			DNSNames:        x509RoleCert.DNSNames,
			X509Certificate: roleCert.X509Certificate + intermediateCerts, // Concatenate intermediate certificate with the role certificate
		})

	}

	return rolecerts, keyPEM, nil
}

// DeleteX509CertRecord makes ZTS API calls to delete the X.509 certificate record
func (h *identityHandler) DeleteX509CertRecord() error {
	if !h.idCfg.Init {
		err := h.client.DeleteInstanceIdentity(
			zts.ServiceName(h.idCfg.ServiceCert.CopperArgos.Provider),
			zts.DomainName(h.domain),
			zts.SimpleName(h.service),
			zts.PathElement(h.idCfg.PodUID),
		)
		if err != nil {
			return fmt.Errorf("Failed to call DeleteInstanceIdentity, err: %v", err)
		}
	}

	return nil
}

// Domain returns the mapped Athenz domain
func (h *identityHandler) Domain() string {
	return h.domain
}

// Service returns the Athenz service name
func (h *identityHandler) Service() string {
	return h.service
}

// InstanceID returns the Instance ID for the cloud
func (h *identityHandler) InstanceID() string {
	return h.instanceID
}

// PrepareIdentityCsrOptions prepares csrOptions for an X.509 certificate
func PrepareIdentityCsrOptions(idCfg *config.IdentityConfig, domain, service string) (*util.CSROptions, error) {

	if !idCfg.ServiceCert.CopperArgos.Use {
		log.Debugf("Skipping to prepare csr with provider service[%s]", idCfg.ServiceCert.CopperArgos.Provider)
		return nil, nil
	}

	domainDNSPart := extutil.DomainToDNSPart(domain)

	spiffeURI, err := extutil.ServiceSpiffeURI(domain, service)
	if err != nil {
		return nil, err
	}

	sans := []string{
		fmt.Sprintf("%s.%s.%s", service, domainDNSPart, idCfg.DNSSuffix),
		fmt.Sprintf("*.%s.%s.%s", service, domainDNSPart, idCfg.DNSSuffix),
		fmt.Sprintf("%s.instanceid.athenz.%s", idCfg.PodUID, idCfg.DNSSuffix),
	}

	if len(idCfg.CertExtraSANDNSs) > 0 {
		sans = append(sans, idCfg.CertExtraSANDNSs...)
		log.Debugf("Requesting with Additional SAN DNSs%v, length[%d]", sans, len(sans))
	}

	subject := pkix.Name{
		Country: func() []string {
			if config.DEFAULT_COUNTRY != "" {
				return []string{config.DEFAULT_COUNTRY}
			}
			return nil
		}(),
		Province: func() []string {
			if config.DEFAULT_PROVINCE != "" {
				return []string{config.DEFAULT_PROVINCE}
			}
			return nil
		}(),
		Organization: func() []string {
			if config.DEFAULT_ORGANIZATION != "" {
				return []string{config.DEFAULT_ORGANIZATION}
			}
			return nil
		}(),
		OrganizationalUnit: []string{idCfg.ServiceCert.CopperArgos.Provider},
		CommonName:         fmt.Sprintf("%s.%s", domain, service),
	}

	csrOptions := &util.CSROptions{
		Subject: subject,
		SANs: util.SubjectAlternateNames{
			DNSNames: sans,
			URIs:     []url.URL{*spiffeURI},
		},
	}

	if idCfg.PodIP != nil {
		csrOptions.SANs.IPAddresses = []net.IP{idCfg.PodIP}
	}

	return csrOptions, nil
}

// PrepareRoleCsrOptions prepares csrOptions for an X.509 certificate
func PrepareRoleCsrOptions(idCfg *config.IdentityConfig, domain, service string) (*[]util.CSROptions, error) {

	var roleCsrOptions []util.CSROptions

	if !idCfg.RoleCert.Use {
		log.Debugf("Skipping to prepare csr for role certificates with target roles[%s], filename format[%s]", idCfg.RoleCert.TargetDomainRoles, idCfg.RoleCert.Format)
		return nil, nil
	}

	for _, dr := range idCfg.RoleCert.TargetDomainRoles {
		targetDomain, targetRole := dr.Domain, dr.Role

		domainDNSPart := extutil.DomainToDNSPart(domain)

		spiffeURI, err := extutil.RoleSpiffeURI(targetDomain, targetRole)
		if err != nil {
			return nil, err
		}

		sans := []string{
			fmt.Sprintf("%s.%s.%s", service, domainDNSPart, idCfg.DNSSuffix),
		}

		subject := pkix.Name{
			Country: func() []string {
				if config.DEFAULT_COUNTRY != "" {
					return []string{config.DEFAULT_COUNTRY}
				}
				return nil
			}(),
			Province: func() []string {
				if config.DEFAULT_PROVINCE != "" {
					return []string{config.DEFAULT_PROVINCE}
				}
				return nil
			}(),
			Organization: func() []string {
				if config.DEFAULT_ORGANIZATION != "" {
					return []string{config.DEFAULT_ORGANIZATION}
				}
				return nil
			}(),
			OrganizationalUnit: []string{config.DEFAULT_ORGANIZATIONAL_UNIT},
			CommonName:         fmt.Sprintf("%s:role.%s", targetDomain, targetRole),
		}

		roleCsrOption := util.CSROptions{
			Subject: subject,
			SANs: util.SubjectAlternateNames{
				DNSNames: sans,
				URIs: []url.URL{
					*spiffeURI,
				},
				EmailAddresses: []string{
					fmt.Sprintf("%s.%s@%s", domain, service, idCfg.DNSSuffix),
				},
			},
		}

		if idCfg.PodIP != nil {
			roleCsrOption.SANs.IPAddresses = []net.IP{idCfg.PodIP}
		}

		roleCsrOptions = append(roleCsrOptions, roleCsrOption)
	}

	return &roleCsrOptions, nil
}

// InstanceIdentityFromPEMBytes returns an InstanceIdentity from its supplied PEM representation.
func InstanceIdentityFromPEMBytes(pemBytes []byte) (identity *InstanceIdentity, err error) {
	identity = &InstanceIdentity{
		X509CertificatePEM: string(pemBytes),
	}
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil && len(rest) > 0 {
			return nil, fmt.Errorf("Failed to decode x509 certificate pem")
		}
		if len(rest) == 0 {
			identity.X509CACertificatePEM = string(pemBytes)
		}
		pemBytes = rest
	}

	return identity, nil
}

func extractServiceDetailsFromCert(cert *x509.Certificate) (string, string, error) {
	cn := cert.Subject.CommonName
	idx := strings.LastIndex(cn, ".")
	if idx < 0 {
		for _, v := range cert.URIs {
			if "spiffe" == v.Scheme {
				spiffePattern := regexp.MustCompile(`spiffe://(.*)/ns/(.*)/sa/(.*)`)
				match := spiffePattern.FindStringSubmatch(v.String())
				if len(match) == 4 {
					return match[2], match[3], nil
				}
				spiffeGlobalPattern := regexp.MustCompile(`spiffe://(.*)/sa/(.*)`)
				match = spiffeGlobalPattern.FindStringSubmatch(v.String())
				if len(match) == 3 {
					return match[1], match[2], nil
				}
			}
		}
		return "", "", fmt.Errorf("Failed to determine domain/service from certificate: CommonName[%s], URIs[%v]", cert.Subject.CommonName, cert.URIs)
	}
	return cn[:idx], cn[idx+1:], nil
}

// PrivateKeyFromPEMBytes returns a private key along with its type from its supplied
// PEM representation.
func PrivateKeyFromPEMBytes(privatePEMBytes []byte) (crypto.Signer, error) {
	k, _, err := athenzutils.ExtractSignerInfo(privatePEMBytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid private key bytes: %w", err)
	}
	return k, nil
}
