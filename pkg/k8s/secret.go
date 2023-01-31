package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyconfigcorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applyconfigmetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// API client for managing Kubernetes Secrets
type SecretsClient struct {
	client    typedcorev1.SecretInterface
	name      string
	namespace string
}

// NewSecretClient initializes Kubernetes SecretClient
func NewSecretClient(name, namespace string) (*SecretsClient, error) {
	// creates the in-cluster config
	// Kubernetes ServiceAccountToken will be automatically refreshed
	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/rest/config.go#L508-L542
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	// Example: https://github.com/kubernetes/client-go/blob/v0.23.5/examples/in-cluster-client-configuration/main.go
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &SecretsClient{
		// Example: https://github.com/kubernetes/client-go/blob/v0.23.5/examples/in-cluster-client-configuration/main.go
		client:    clientset.CoreV1().Secrets(namespace),
		name:      name,
		namespace: namespace,
	}, nil
}

// GetIdentitySecret gets Kubernetes Secret
func (c *SecretsClient) GetIdentitySecret() (secret *corev1.Secret, isNotFound bool, err error) {
	// Type: "k8s.io/api/core/v1".Secret
	// See: https://github.com/kubernetes/api/blob/v0.23.5/core/v1/types.go#L6003-L6038
	secret, err = c.client.Get(context.TODO(), c.name, metav1.GetOptions{})

	// Examples for error handling:
	// - Use helper functions like e.g. errors.IsNotFound()
	// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message
	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/examples/out-of-cluster-client-configuration/main.go#L75-L85
	if errors.IsNotFound(err) {
		return nil, true, fmt.Errorf("secret [%s] in namespace [%s] not found\n", c.name, c.namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		err = fmt.Errorf("Error getting secret [%s] in namespace [%s]: %v\n", c.name, c.namespace, statusError.ErrStatus.Message)
		return nil, false, err
	}

	return secret, false, err
}

// GetKeyAndCertificateFromSecret converts Kubernetes Secret to key pem and cert pem
func GetKeyAndCertificateFromSecret(secret *corev1.Secret) ([]byte, []byte) {
	// Type: "k8s.io/api/core/v1".Secret.Data
	// See: https://github.com/kubernetes/api/blob/v0.23.5/core/v1/types.go#L6019-L6024
	// Type: "k8s.io/api/core/v1".TLSPrivateKeyKey
	// See: https://github.com/kubernetes/api/blob/v0.23.5/core/v1/types.go#L6119-L6120
	// Type: "k8s.io/api/core/v1".TLSCertKey
	// See: https://github.com/kubernetes/api/blob/v0.23.5/core/v1/types.go#L6117-L6118
	return secret.Data[corev1.TLSPrivateKeyKey], secret.Data[corev1.TLSCertKey]
}

// CreateIdentitySecret creates Kubernetes Secret
func (c *SecretsClient) CreateIdentitySecret(key, cert []byte) (*corev1.Secret, error) {
	secret := prepareNewTLSSecret(c.name, c.namespace, key, cert)

	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/kubernetes/typed/core/v1/secret.go#L115-L126
	return c.client.Create(context.TODO(), secret, metav1.CreateOptions{})
}

// CreateIdentitySecret updates Kubernetes Secret
func (c *SecretsClient) UpdateIdentitySecret(key, cert []byte) (*corev1.Secret, error) {
	secret := prepareNewTLSSecret(c.name, c.namespace, key, cert)

	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/kubernetes/typed/core/v1/secret.go#L128-L140
	return c.client.Update(context.TODO(), secret, metav1.UpdateOptions{})
}

// CreateIdentitySecret applies/patches Kubernetes Secret
func (c *SecretsClient) ApplyIdentitySecret(key, cert []byte) (*corev1.Secret, error) {
	secret := prepareNewTLSSecret(c.name, c.namespace, key, cert)
	// Type: "k8s.io/client-go/applyconfigurations/core/v1".SecretApplyConfiguration
	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/applyconfigurations/core/v1/secret.go
	applyConfig := &applyconfigcorev1.SecretApplyConfiguration{
		TypeMetaApplyConfiguration: applyconfigmetav1.TypeMetaApplyConfiguration{
			Kind:       &secret.TypeMeta.Kind,
			APIVersion: &secret.TypeMeta.APIVersion,
		},
		ObjectMetaApplyConfiguration: &applyconfigmetav1.ObjectMetaApplyConfiguration{
			Name:        &secret.Name,
			Labels:      secret.Labels,
			Annotations: secret.Annotations,
		},
		Type:       &secret.Type,
		Data:       secret.Data,
		StringData: secret.StringData,
		Immutable:  secret.Immutable,
	}

	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/kubernetes/typed/core/v1/secret.go#L184-L208
	return c.client.Apply(context.TODO(), applyConfig, metav1.ApplyOptions{FieldManager: "athenz-sia-server-side-apply", Force: true})
}

func prepareNewTLSSecret(name, namespace string, key, cert []byte) *corev1.Secret {
	// Type: "k8s.io/api/core/v1".Secret
	// See: https://github.com/kubernetes/api/blob/v0.23.5/core/v1/types.go#L6003-L6038
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		// See: https://github.com/kubernetes/kubernetes/blob/v1.23.5/pkg/apis/core/types.go#L5259-L5272
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: key,  // TLSPrivateKeyKey = "tls.key"
			corev1.TLSCertKey:       cert, // TLSCertKey = "tls.crt"
		},
		// Type: "k8s.io/api/core/v1".SecretTypeTLS
		// See: https://github.com/kubernetes/kubernetes/blob/v1.23.5/pkg/apis/core/types.go#L5259-L5267
		Type: corev1.SecretTypeTLS,
	}
}
