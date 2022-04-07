package identity

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"

	extutil "github.com/AthenZ/k8s-athenz-sia/pkg/util"
)

// IdentityConfig from cmd line args
type IdentityConfig struct {
	Init              bool
	KeyFile           string
	CertFile          string
	CaCertFile        string
	Refresh           time.Duration
	Reloader          *util.CertReloader
	ServerCACert      string
	SaTokenFile       string
	Endpoint          string
	ProviderService   string
	DNSSuffix         string
	Namespace         string
	ServiceAccount    string
	PodIP             string
	PodUID            string
	RoleCertDir       string
	TargetDomainRoles string
}

type RoleCertificate struct {
	Domain          string
	Role            string
	Subject         pkix.Name
	Issuer          pkix.Name
	NotBefore       time.Time
	NotAfter        time.Time
	SerialNumber    *big.Int
	X509Certificate string
}

type identityHandler struct {
	config         *IdentityConfig
	client         zts.ZTSClient
	domain         string
	service        string
	instanceid     string
	csrOptions     util.CSROptions
	roleCsrOptions *[]util.CSROptions
}

var DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER = 5 // Expiry time buffer for role certificates in minutes (5 mins)

// default values for X.509 certificate signing request
var DEFAULT_COUNTRY = "US"
var DEFAULT_PROVINCE = ""
var DEFAULT_ORGANIZATION = ""
var DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"

// InitIdentityHandler initializes the ZTS client and parses the config to create CSR options
func InitIdentityHandler(config *IdentityConfig) (*identityHandler, error) {

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if !config.Init {
		tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return config.Reloader.GetLatestCertificate()
		}
	}

	t := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if config.ServerCACert != "" {
		certPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(config.ServerCACert)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = certPool
		t.TLSClientConfig = tlsConfig
	}

	client := zts.NewClient(config.Endpoint, t)

	domain := extutil.NamespaceToDomain(config.Namespace)
	service := extutil.ServiceAccountToService(config.ServiceAccount)

	csrOptions, err := PrepareIdentityCsrOptions(config, domain, service)
	if err != nil {
		return nil, err
	}
	roleCsrOptions, err := PrepareRoleCsrOptions(config, domain, service)
	if err != nil {
		return nil, err
	}

	return &identityHandler{
		config:         config,
		client:         client,
		domain:         domain,
		service:        service,
		instanceid:     config.PodUID,
		csrOptions:     *csrOptions,
		roleCsrOptions: roleCsrOptions,
	}, nil
}

// GetX509Cert makes ZTS API calls to generate an X.509 certificate
func (h *identityHandler) GetX509Cert() (*zts.InstanceIdentity, []byte, error) {
	keyPEM, csrPEM, err := util.GenerateKeyAndCSR(h.csrOptions)
	if err != nil {
		return nil, nil, err
	}

	saToken, err := ioutil.ReadFile(h.config.SaTokenFile)
	if err != nil {
		return nil, nil, err
	}

	var id *zts.InstanceIdentity
	if h.config.Init {
		id, _, err = h.client.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
			Provider:        zts.ServiceName(h.config.ProviderService),
			Domain:          zts.DomainName(h.domain),
			Service:         zts.SimpleName(h.service),
			AttestationData: string(saToken),
			Csr:             string(csrPEM),
		})
		return id, keyPEM, err
	}

	id, err = h.client.PostInstanceRefreshInformation(
		zts.ServiceName(h.config.ProviderService),
		zts.DomainName(h.domain),
		zts.SimpleName(h.service),
		zts.PathElement(h.config.PodUID),
		&zts.InstanceRefreshInformation{
			AttestationData: string(saToken),
			Csr:             string(csrPEM),
		})

	return id, keyPEM, err
}

// GetX509RoleCert makes ZTS API calls to generate an X.509 role certificate
func (h *identityHandler) GetX509RoleCert(id *zts.InstanceIdentity, keyPEM []byte) (rolecerts [](*RoleCertificate), err error) {

	if h.roleCsrOptions != nil {
		for _, csrOption := range *h.roleCsrOptions {
			dr := strings.Split(csrOption.Subject.CommonName, ":role.")

			cert, err := tls.X509KeyPair([]byte(id.X509Certificate+id.X509CertificateSigner), keyPEM)
			if err != nil {
				return nil, fmt.Errorf("Failed to set tls client key pair for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
			}
			t := &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:   tls.VersionTLS12,
					Certificates: []tls.Certificate{cert},
				},
			}
			if h.config.ServerCACert != "" {
				certPool := x509.NewCertPool()
				caCert, err := ioutil.ReadFile(h.config.ServerCACert)
				if err != nil {
					return nil, fmt.Errorf("Failed to set tls client ca cert for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
				}
				certPool.AppendCertsFromPEM(caCert)
				t.TLSClientConfig.RootCAs = certPool
			}

			_, key, err := util.PrivateKeyFromPEMBytes(keyPEM)
			if err != nil {
				return nil, fmt.Errorf("Failed to prepare csr, failed to read private key pem bytes for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
			}
			roleCsrPEM, err := util.GenerateCSR(key, csrOption)
			if err != nil {
				return nil, fmt.Errorf("Failed to prepare csr, failed to generate csr for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
			}
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("Failed to prepare csr, failed to parse certificate for PostRoleCertificateRequest, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
			}
			roleRequest := &zts.RoleCertificateRequest{
				Csr:        string(roleCsrPEM),
				ExpiryTime: int64(x509Cert.NotAfter.Sub(time.Now()).Minutes()) + int64(DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER), // Extract NotAfter from the instance certificate
			}

			// In init mode, the existing ZTS Client does not have client certificate set.
			// When config.Reloader.GetLatestCertificate() is called to load client certificate, the first certificate has not written to the file yet.
			// Therefore, ZTS Client must be renewed to make sure the ZTS Client loads the latest client certificate.
			//
			// The intermediate certificates may be different between each ZTS.
			// Therefore, ZTS Client for PostRoleCertificateRequest must share the same endpoint as PostInstanceRegisterInformation/PostInstanceRefreshInformation
			roleCertClient := zts.NewClient(h.config.Endpoint, t)
			// PostRoleCertificateRequest must be called instead of PostRoleCertificateRequestExt,
			//     since the current version 1.9.21-SNAPSHOT set Principal Name in the Subject CommonName with PostRoleCertificateRequestExt API.
			// Setting Principal Name in the Subject CommonName is not compatible with mTLS role-based authorization.
			//
			// See:
			//     https://github.com/AthenZ/athenz/blob/c60c90a3fa14d82eb4bd3a789a3243b7f97d0efe/pom.xml#L23
			//     https://github.com/AthenZ/blob/c60c90a3fa14d82eb4bd3a789a3243b7f97d0efe/servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSImpl.java#L2229
			//     https://github.com/AthenZ/athenz/blob/c60c90a3fa14d82eb4bd3a789a3243b7f97d0efe/servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSImpl.java#L2283
			//     https://github.com/AthenZ/athenz/blob/c60c90a3fa14d82eb4bd3a789a3243b7f97d0efe/servers/zts/src/main/java/com/yahoo/athenz/zts/cert/X509RoleCertRequest.java#L209
			roleCert, err := roleCertClient.PostRoleCertificateRequest(zts.DomainName(dr[0]), zts.EntityName(dr[1]), roleRequest)
			if err != nil {
				return nil, fmt.Errorf("PostRoleCertificateRequest failed for Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
			}
			x509RoleCert, err := util.CertificateFromPEMBytes([]byte(roleCert.Token))
			if err != nil {
				return nil, fmt.Errorf("Failed to parse x509 cert for PostRoleCertificateRequest response, Subject CommonName[%s], err: %v", csrOption.Subject.CommonName, err)
			}
			rolecerts = append(rolecerts, &RoleCertificate{
				Domain:          dr[0],
				Role:            dr[1],
				Subject:         x509RoleCert.Subject,
				Issuer:          x509RoleCert.Issuer,
				NotBefore:       x509RoleCert.NotBefore,
				NotAfter:        x509RoleCert.NotAfter,
				SerialNumber:    x509RoleCert.SerialNumber,
				X509Certificate: roleCert.Token + id.X509CertificateSigner, // Concatenate intermediate certificate with the role certificate
			})

		}
	}

	return rolecerts, err
}

// DeleteX509CertRecord makes ZTS API calls to delete the X.509 certificate record
func (h *identityHandler) DeleteX509CertRecord() (err error) {
	if !h.config.Init {
		err = h.client.DeleteInstanceIdentity(
			zts.ServiceName(h.config.ProviderService),
			zts.DomainName(h.domain),
			zts.SimpleName(h.service),
			zts.PathElement(h.config.PodUID),
		)
	}

	return
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
	return h.instanceid
}

// PrepareIdentityCsrOptions prepares csrOptions for an X.509 certificate
func PrepareIdentityCsrOptions(config *IdentityConfig, domain, service string) (*util.CSROptions, error) {

	domainDNSPart := extutil.DomainToDNSPart(domain)

	ip := net.ParseIP(config.PodIP)
	if ip == nil {
		return nil, errors.New("pod IP is nil")
	}
	spiffeURI, err := extutil.ServiceSpiffeURI(domain, service)
	if err != nil {
		return nil, err
	}

	sans := []string{
		fmt.Sprintf("%s.%s.%s", service, domainDNSPart, config.DNSSuffix),
		fmt.Sprintf("*.%s.%s.%s", service, domainDNSPart, config.DNSSuffix),
		fmt.Sprintf("%s.instanceid.athenz.%s", config.PodUID, config.DNSSuffix),
	}

	subject := pkix.Name{
		Country:            []string{DEFAULT_COUNTRY},
		Province:           []string{DEFAULT_PROVINCE},
		Organization:       []string{DEFAULT_ORGANIZATION},
		OrganizationalUnit: []string{config.ProviderService},
		CommonName:         fmt.Sprintf("%s.%s", domain, service),
	}

	return &util.CSROptions{
		Subject: subject,
		SANs: util.SubjectAlternateNames{
			DNSNames:    sans,
			IPAddresses: []net.IP{ip},
			URIs:        []url.URL{*spiffeURI},
		},
	}, nil
}

// PrepareRoleCsrOptions prepares csrOptions for an X.509 certificate
func PrepareRoleCsrOptions(config *IdentityConfig, domain, service string) (*[]util.CSROptions, error) {

	if config.TargetDomainRoles == "" {
		return nil, nil
	}

	var roleCsrOptions []util.CSROptions

	for _, domainrole := range strings.Split(config.TargetDomainRoles, ",") {
		// referred to SplitRoleName()
		// https://github.com/AthenZ/athenz/blob/73b25572656f289cce501b4c2fe78f86656082e7/libs/go/sia/util/util.go#L69-L78
		dr := strings.Split(domainrole, ":role.")
		if len(dr) != 2 || len(dr[0]) == 0 || len(dr[1]) == 0 {
			return nil, fmt.Errorf("Invalid role name: '%s', expected format {domain}:role.{role}", domainrole)
		}
		targetDomain := dr[0]
		targetRole := dr[1]

		domainDNSPart := extutil.DomainToDNSPart(domain)

		ip := net.ParseIP(config.PodIP)
		if ip == nil {
			return nil, errors.New("pod IP is nil")
		}
		spiffeURI, err := extutil.RoleSpiffeURI(targetDomain, targetRole)
		if err != nil {
			return nil, err
		}

		sans := []string{
			fmt.Sprintf("%s.%s.%s", service, domainDNSPart, config.DNSSuffix),
		}

		subject := pkix.Name{
			Country:            []string{DEFAULT_COUNTRY},
			Province:           []string{DEFAULT_PROVINCE},
			Organization:       []string{DEFAULT_ORGANIZATION},
			OrganizationalUnit: []string{DEFAULT_ORGANIZATIONAL_UNIT},
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
					fmt.Sprintf("%s.%s@%s", domain, service, config.DNSSuffix),
				},
			},
		}

		roleCsrOptions = append(roleCsrOptions, roleCsrOption)
	}

	return &roleCsrOptions, nil
}
