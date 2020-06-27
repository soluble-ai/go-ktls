// Copyright 2020 Soluble Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ktls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

// TLSSecret makes a best-effort attempt to get you a TLS certificate,
// resorting to generating a certificate on-the-fly and saving it in
// a secret if necessary.
type TLSSecret struct {
	// Explicitly provide a KubeClient to lookup a TLS secret and possibly generate
	// a certificate on-the-fly.  Even if you don't provide one TLSSecret will try
	// and get a "default" one for you.
	ExplicitKubeClient       kubernetes.Interface
	DisableDefaultKubeClient bool
	// The namespace for the certificate
	Namespace string
	// The name of the secret
	Name string
	// The name of the CA secret, defaults to Name-ca
	CAName string
	// The duration of the CA certifcate, defaults to 1 year
	CADuration time.Duration
	// The duration of the TLS certificate, defaults to 8 hours
	Duration time.Duration
	DNSNames []string
	// Custom log output
	Log func(string, ...interface{})

	lock            sync.Mutex
	tlsCertificate  *tls.Certificate
	renewalTime     time.Time
	kubeClient      kubernetes.Interface
	kubeClientError error
}

func (t *TLSSecret) logf(format string, values ...interface{}) {
	if t.Log != nil {
		t.Log(format, values...)
	} else {
		log.Printf(format, values...)
	}
}

func (t *TLSSecret) GetNamespace() string {
	if t.Namespace != "" {
		return t.Namespace
	}
	return "default"
}

func (t *TLSSecret) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		GetCertificate: t.getTLSCertificate,
	}, nil
}

func (t *TLSSecret) getTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.tlsCertificate == nil || time.Now().After(t.renewalTime) {
		ckp, err := t.GetCertificateKeyPair()
		if err != nil {
			t.logf("Could not get certificate: %s", err.Error())
			return nil, nil
		}
		t.tlsCertificate = ckp.GetTLSCertificateChain()
		x509cert, err := ckp.GetParsedCertificate()
		if err != nil {
			t.logf("Could not parse generated certificate: %s", err.Error())
			t.renewalTime = time.Now().Add(time.Minute)
		} else {
			t.renewalTime = x509cert.NotAfter.Add(-15 * time.Minute)
		}
	}
	return t.tlsCertificate, nil
}

func (t *TLSSecret) MustGetTLSConfig() *tls.Config {
	config, err := t.GetTLSConfig()
	if err != nil {
		panic(err)
	}
	return config
}

func (t *TLSSecret) GetKubeClient() kubernetes.Interface {
	if t.ExplicitKubeClient != nil {
		return t.ExplicitKubeClient
	}
	if !t.DisableDefaultKubeClient && t.kubeClient == nil && t.kubeClientError == nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err == nil {
			t.kubeClient, err = kubernetes.NewForConfig(config)
		}
		if err != nil {
			t.logf("Failed to get a kubernetes client: %s", err.Error())
			t.kubeClientError = err
		}
	}
	return t.kubeClient
}

func (t *TLSSecret) getSecret(name string) (*corev1.Secret, error) {
	if t.GetKubeClient() == nil || name == "" {
		return nil, nil
	}
	secret, err := t.GetKubeClient().CoreV1().Secrets(t.GetNamespace()).Get(context.TODO(), name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (t *TLSSecret) GetCertificateKeyPair() (*CertificateKeyPair, error) {
	ckp, _, err := t.getSecretCertificate(t.Name, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if ckp == nil {
		if t.Name == "" {
			return nil, fmt.Errorf("the TLSSecret Name must be set")
		}
		if t.GetKubeClient() == nil {
			return nil, fmt.Errorf("cannot create secret if kubernetes client is not available")
		}
		var err error
		ckp, err = t.generateCert()
		if err != nil {
			return nil, err
		}
	}
	return ckp, nil
}

func (t *TLSSecret) getSecretCertificate(name string, d time.Duration) (*CertificateKeyPair, *corev1.Secret, error) {
	secret, err := t.getSecret(name)
	if err != nil {
		return nil, nil, err
	}
	if secret != nil && secret.Data != nil {
		ckp := &CertificateKeyPair{
			KeyPem:  getSecretData(secret, corev1.TLSPrivateKeyKey),
			CertPem: getSecretData(secret, corev1.TLSCertKey),
		}
		if ckp.IsValid(d) {
			t.logf("Using TLS secret from %s/%s valid for at least %s", t.GetNamespace(), name, d)
			return ckp, secret, nil
		}
	}
	return nil, secret, nil
}

func (t *TLSSecret) getCertDuration() time.Duration {
	duration := t.Duration
	if duration == 0 {
		duration = 8 * time.Hour
	}
	return duration
}

func (t *TLSSecret) getCACertDuration() time.Duration {
	caDuration := t.CADuration
	if caDuration == 0 {
		caDuration = 365 * 24 * time.Hour
	}
	return caDuration
}

func (t *TLSSecret) generateCert() (*CertificateKeyPair, error) {
	var err error
	caName := t.CAName
	if caName == "" {
		caName = t.Name + "-ca"
	}
	var caCert *CertificateKeyPair
	var cert *CertificateKeyPair
	caCert, _, err = t.getSecretCertificate(caName, time.Hour)
	caDuration := t.getCACertDuration()
	if caDuration < 8*time.Hour {
		return nil, fmt.Errorf("CA duration must be at least 8 hours")
	}
	certDuration := t.getCertDuration()
	if certDuration < 30*time.Minute {
		return nil, fmt.Errorf("cert duration must be at least 30 minutes")
	}
	if err == nil {
		if caCert == nil || !caCert.IsValid(time.Hour) {
			t.logf("Generating new CA certificate %s/%s", t.GetNamespace(), caName)
			caCert, err = GenerateCert(caName, nil, nil, caDuration)
			if err == nil {
				err = t.persistCert(caCert, caName)
			}
		}
		if err == nil {
			t.logf("Generating new TLS certificate %s/%s", t.GetNamespace(), t.Name)
			cert, err = GenerateCert(t.Name, t.DNSNames, caCert, certDuration)
			if err == nil {
				err = t.persistCert(cert, t.Name)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (t *TLSSecret) persistCert(ckp *CertificateKeyPair, name string) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		c, secret, err := t.getSecretCertificate(name, time.Minute)
		if err != nil {
			return err
		}
		if c != nil {
			t.logf("Updated certificate is now valid")
			ckp.CopyFrom(c)
			return nil
		}
		secretData := map[string][]byte{
			corev1.TLSCertKey:       ckp.CertPem,
			corev1.TLSPrivateKeyKey: ckp.KeyPem,
		}
		if secret == nil {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
				Type: corev1.SecretTypeTLS,
				Data: secretData,
			}
			_, err := t.GetKubeClient().CoreV1().Secrets(t.GetNamespace()).Create(context.TODO(), secret, metav1.CreateOptions{})
			return err
		}
		secret.Type = corev1.SecretTypeTLS
		secret.Data = secretData
		_, err = t.GetKubeClient().CoreV1().Secrets(t.GetNamespace()).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err == nil {
			t.logf("Saved secret %s/%s", t.GetNamespace(), name)
		}
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func getSecretData(secret *corev1.Secret, name string) []byte {
	if secret.Data == nil {
		return nil
	}
	return secret.Data[name]
}
