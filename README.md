# k8s-athenz-sia

## Lifecycle

```mermaid
  graph TD;
      A[Bootup]==>B[Initialize configurations<br/> (delay within configured jitter seconds)];
      B==>C[Create/Refresh x509 certs<br/> in every configured period];
      C==>D{Attempt to<br/> create/refresh x509 instance cert<br/> from identity provider};
      D==>E[Success];
      D-->E'[Failure];
      E'-->F{Attempt to<br/> load x509 instance cert temporary backup<br/> from kubernetes secret}
      F==>G[Success];
      G==>J
      F-->G'[Failure];
      G'-->C
      F==>G''[No kubernetes secret configured];
      G''==>J
      E==>H{Attempt to<br/> save x509 instance cert<br/> to kubernetes secret};
      H==>I[Success];
      H-->I'[Failure];
      I'-->C
      H==>I''[No kubernetes secret configured];
      I''==>J
      I==>J{Attempt to<br/> retrieve x509 role certs<br/> from identity provider};
      J==>K[Success];
      J-->K'[Failure];
      J==>K''[No roles configured];
      K''==>N
      K==>L{Write x509 instance/role certs to volume}
      L==>M[Success];
      L-->M'[Failure];
      M'-->C
      M==>C
      K'==>N{Write x509 instance cert to volume}
      N==>O[Success];
      N-->O'[Failure];
      O'-->C
      O==>C
```

## Usage
```
Usage of athenz-sia:
  -backup-mode string
    	Kubernetes secret backup mode, must be one of read or write (Note: Performing writes with a large number of concurrency may cause unexpected loads on k8s api) (default "read")
  -delay-jitter-seconds int
    	delay boot with random jitter within the specified seconds (0 to disable)
  -delete-instance-id
    	delete x509 cert record from identity provider when stop signal is sent (default true)
  -dns-suffix string
    	DNS Suffix for certs
  -endpoint string
    	Athenz ZTS endpoint
  -log-dir string
    	directory to store the server log files (default "/var/log/athenz-sia")
  -log-level string
    	logging level (default "INFO")
  -mode string
    	mode, must be one of init or refresh, required (default "init")
  -out-ca-cert string
    	CA cert file to write (default "/var/run/athenz/ca.cert.pem")
  -out-cert string
    	cert file to write (default "/var/run/athenz/service.cert.pem")
  -out-cert-secret string
    	Kubernetes secret name to backup cert (Backup will be disabled if empty)
  -out-key string
    	key file to write (default "/var/run/athenz/service.key.pem")
  -out-rolecert-dir string
    	directory to write cert file for role certificates (default "/var/run/athenz/")
  -provider-service string
    	Identity Provider service
  -refresh-interval string
    	cert refresh interval (default "24h")
  -sa-token-file string
    	bound sa jwt token file location (default "/var/run/secrets/kubernetes.io/bound-serviceaccount/token")
  -server-ca-cert string
    	path to CA cert file to verify ZTS server certs
  -target-domain-roles string
    	target Athenz roles with domain (e.g. athenz.subdomain:role.admin,sys.auth:role.providers)
```
