package config

import (
	"strconv"
	"time"
)

const (
	serviceName = "athenz-sia"

	DEFAULT_SIDECAR_CONFIG_PATH = "/etc/athenz/client/config.yaml"
)

var (
	// default values for X.509 certificate signing request
	DEFAULT_COUNTRY             = "US"
	DEFAULT_PROVINCE            string
	DEFAULT_ORGANIZATION        string
	DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"

	DEFAULT_POLL_TOKEN_INTERVAL = 4 * time.Hour

	// default values for role tokens and access tokens
	DEFAULT_TOKEN_EXPIRY_TIME     = "120"
	DEFAULT_TOKEN_EXPIRY_TIME_INT int

	// DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES may be overwritten with go build option (e.g. "-X identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES=5")
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES     = "5"
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT int

	DEFAULT_ENDPOINT                     string
	DEFAULT_ROLE_AUTH_HEADER             = "Athenz-Role-Auth"
	DEFAULT_DNS_SUFFIX                   = "athenz.cloud"
	DEFAULT_ROLE_CERT_FILENAME_DELIMITER = ":role."
	DEFAULT_INTERMEDIATE_CERT_BUNDLE     string
)

func init() {
	// initializes default values from build args
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT, _ = strconv.Atoi(DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES)
	DEFAULT_TOKEN_EXPIRY_TIME_INT, _ = strconv.Atoi(DEFAULT_TOKEN_EXPIRY_TIME)
}
