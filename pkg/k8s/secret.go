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

package k8s

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	saName    string
	saUID     string
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

	// get service account info from the token (token verification is done by API server)
	token, _, err := jwt.NewParser().ParseUnverified(config.BearerToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	claims, _ = claims["kubernetes.io"].(map[string]interface{})
	claims, _ = claims["serviceaccount"].(map[string]interface{})
	saName := claims["name"].(string)
	saUID := claims["uid"].(string)

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
		saName:    saName,
		saUID:     saUID,
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
		return nil, true, fmt.Errorf("secret [%s] in namespace [%s] not found", c.name, c.namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		err = fmt.Errorf("Error getting secret [%s] in namespace [%s]: %s", c.name, c.namespace, statusError.ErrStatus.Message)
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
	secret := c.prepareNewTLSSecret(key, cert)

	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/kubernetes/typed/core/v1/secret.go#L115-L126
	return c.client.Create(context.TODO(), secret, metav1.CreateOptions{})
}

// UpdateIdentitySecret updates Kubernetes Secret
func (c *SecretsClient) UpdateIdentitySecret(key, cert []byte) (*corev1.Secret, error) {
	secret := c.prepareNewTLSSecret(key, cert)

	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/kubernetes/typed/core/v1/secret.go#L128-L140
	return c.client.Update(context.TODO(), secret, metav1.UpdateOptions{})
}

// ApplyIdentitySecret applies/patches Kubernetes Secret
func (c *SecretsClient) ApplyIdentitySecret(key, cert []byte) (*corev1.Secret, error) {
	secret := c.prepareNewTLSSecret(key, cert)
	ors := make([]applyconfigmetav1.OwnerReferenceApplyConfiguration, len(secret.OwnerReferences))
	for i, or := range secret.OwnerReferences {
		ac := *applyconfigmetav1.OwnerReference().
			WithAPIVersion(or.APIVersion).
			WithKind(or.Kind).
			WithName(or.Name).
			WithUID(or.UID)
		if or.Controller != nil {
			ac.WithController(*or.Controller)
		}
		if or.BlockOwnerDeletion != nil {
			ac.WithBlockOwnerDeletion(*or.BlockOwnerDeletion)
		}
		ors[i] = ac
	}
	// Type: "k8s.io/client-go/applyconfigurations/core/v1".SecretApplyConfiguration
	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/applyconfigurations/core/v1/secret.go
	applyConfig := &applyconfigcorev1.SecretApplyConfiguration{
		TypeMetaApplyConfiguration: applyconfigmetav1.TypeMetaApplyConfiguration{
			Kind:       &secret.TypeMeta.Kind,
			APIVersion: &secret.TypeMeta.APIVersion,
		},
		ObjectMetaApplyConfiguration: &applyconfigmetav1.ObjectMetaApplyConfiguration{
			Name:            &secret.Name,
			Labels:          secret.Labels,
			Annotations:     secret.Annotations,
			OwnerReferences: ors,
		},
		Type:       &secret.Type,
		Data:       secret.Data,
		StringData: secret.StringData,
		Immutable:  secret.Immutable,
	}

	// See: https://github.com/kubernetes/client-go/blob/v0.23.5/kubernetes/typed/core/v1/secret.go#L184-L208
	return c.client.Apply(context.TODO(), applyConfig, metav1.ApplyOptions{FieldManager: "athenz-sia-server-side-apply", Force: true})
}

func (c *SecretsClient) prepareNewTLSSecret(key, cert []byte) *corev1.Secret {
	// Type: "k8s.io/api/core/v1".Secret
	// See: https://github.com/kubernetes/api/blob/v0.23.5/core/v1/types.go#L6003-L6038
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.name,
			Namespace: c.namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "ServiceAccount",
					Name:       c.saName,
					UID:        types.UID(c.saUID),
				},
			},
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
