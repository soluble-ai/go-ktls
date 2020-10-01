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

// TLSSecret retrieves a TLS certificate from a kubernetes secret.  If the
// secret doesn't exist, it will generate it.
type TLSSecret struct {
	// Explicitly provide a KubeClient to lookup a TLS secret and possibly generate
	// a certificate on-the-fly.  If unset TLSSecret will try and get one
	// for you.
	ExplicitKubeClient kubernetes.Interface
	// The namespace for the certificate
	Namespace string
	// The name of the secret
	Name string
	// The name of the CA secret, defaults to Name-ca
	CAName string
	// The name of the secret that will hold the public
	// CA certificate.  This duplicates the CAName secret but
	// is missing the "tls.key" entry.
	CAPublicName string
	// The duration of the CA certifcate, defaults to 10 years
	CADuration time.Duration
	// The duration of the TLS certificate, defaults to 8 hours
	Duration time.Duration
	// The DNSNames of the certificate.  If unset, then DNSNames will be Name,
	// Name.Namespace.svc, and Name.Namespace.svc.cluster.local (these values)
	// are appropriate for a service with the name "Name".
	DNSNames []string
	// Enable background refresh
	EnableBackgroundRefresh bool
	// The field manager for update and create operations
	FieldManager string
	// The cluster domain name.  If unset, then "cluster.local"
	ClusterDomainName string

	// Custom log output
	Log func(string, ...interface{})

	lock                     sync.Mutex
	tlsCertificate           *tls.Certificate
	renewalTime              time.Time
	kubeClient               kubernetes.Interface
	backgroundRenewalRunning bool
}

func (t *TLSSecret) logf(format string, values ...interface{}) {
	if t.Log != nil {
		t.Log(format, values...)
	} else {
		log.Printf(format, values...)
	}
}

func (t *TLSSecret) GetTLSConfig() (*tls.Config, error) {
	// get the certificate now to detect errors and to
	// start the background refresh process
	_, err := t.getTLSCertificate(nil)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		GetCertificate: t.getTLSCertificate,
		MinVersion:     tls.VersionTLS12,
	}, nil
}

func (t *TLSSecret) getTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if err := t.validateNames(); err != nil {
		return nil, err
	}
	if t.tlsCertificate == nil || clock.Now().After(t.renewalTime) {
		ckp, err := t.doGetCertificateKeyPair()
		if err != nil {
			t.logf("Could not get certificate: %s", err.Error())
			return nil, nil
		}
		t.tlsCertificate = ckp.GetTLSCertificateChain()
		x509cert, err := ckp.GetParsedCertificate()
		if err != nil {
			t.logf("Could not parse generated certificate: %s", err.Error())
			t.renewalTime = clock.Now().Add(time.Minute)
		} else {
			t.renewalTime = x509cert.NotAfter.Add(-15 * time.Minute)
		}
	}
	if t.EnableBackgroundRefresh && !t.backgroundRenewalRunning {
		t.backgroundRenewalRunning = true
		go t.backgroundRenewal()
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

func (t *TLSSecret) getKubeClient() (kubernetes.Interface, error) {
	if t.ExplicitKubeClient != nil {
		return t.ExplicitKubeClient, nil
	}
	if t.kubeClient == nil {
		kubeClient, err := GetDefaultKubeClient()
		if err != nil {
			return nil, err
		}
		t.kubeClient = kubeClient
	}
	return t.kubeClient, nil
}

func GetDefaultKubeClient() (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func (t *TLSSecret) getSecret(name string) (*corev1.Secret, error) {
	kubeClient, err := t.getKubeClient()
	if err != nil {
		return nil, err
	}
	secret, err := kubeClient.CoreV1().Secrets(t.Namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (t *TLSSecret) GetCertificateKeyPair() (*CertificateKeyPair, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if err := t.validateNames(); err != nil {
		return nil, err
	}
	return t.doGetCertificateKeyPair()
}

func (t *TLSSecret) validateNames() error {
	if t.Name == "" {
		return fmt.Errorf("TLSSecret Name cannot be empty")
	}
	if t.Namespace == "" {
		return fmt.Errorf("TLSSecret Namespace cannot be empty")
	}
	return nil
}

func (t *TLSSecret) doGetCertificateKeyPair() (*CertificateKeyPair, error) {
	ckp, _, err := t.getSecretCertificate(t.Name, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if ckp == nil {
		if t.Name == "" {
			return nil, fmt.Errorf("the TLSSecret Name must be set")
		}
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
			x509Cert, _ := ckp.GetParsedCertificate()
			t.logf("TLS secret from %s/%s valid until %s", t.Namespace, name, x509Cert.NotAfter)
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
		caDuration = 10 * 365 * 24 * time.Hour
	}
	return caDuration
}

func (t *TLSSecret) generateCert() (*CertificateKeyPair, error) {
	var err error
	caName := defaultString(t.CAName, t.Name+"-ca")
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
			t.logf("Generating new CA certificate %s/%s", t.Namespace, caName)
			caCert, err = GenerateCert(caName, nil, nil, caDuration)
			if err == nil {
				err = t.persistCert(caCert, caName, true)
				if err == nil {
					err = t.persistCert(caCert, defaultString(t.CAPublicName, caName+"-public"), false)
				}
			}
		}
		if err == nil {
			t.logf("Generating new TLS certificate %s/%s", t.Namespace, t.Name)
			dnsNames := t.DNSNames
			if len(dnsNames) == 0 {
				dnsNames = []string{
					t.Name,
					fmt.Sprintf("%s.%s", t.Name, t.Namespace),
					fmt.Sprintf("%s.%s.svc", t.Name, t.Namespace),
					fmt.Sprintf("%s.%s.svc.%s", t.Name, t.Namespace, defaultString(t.ClusterDomainName, "cluster.local")),
				}
			}
			cert, err = GenerateCert(t.Name, dnsNames, caCert, certDuration)
			if err == nil {
				err = t.persistCert(cert, t.Name, true)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (t *TLSSecret) persistCert(ckp *CertificateKeyPair, name string, includeKey bool) error {
	kubeClient, err := t.getKubeClient()
	if err != nil {
		return err
	}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		c, secret, err := t.getSecretCertificate(name, time.Minute)
		if err != nil {
			return err
		}
		if c != nil {
			// it's possible another process has updated the cert, in which
			// case we'll use the updated version
			x509Cert, err := c.GetParsedCertificate()
			if err == nil && x509Cert.NotBefore.After(t.renewalTime.Add(-1*time.Minute)) {
				t.logf("Updated certificate is now valid")
				ckp.CopyFrom(c)
				return nil
			}
		}
		secretData := map[string][]byte{
			corev1.TLSCertKey: ckp.CertPem,
		}
		var secretType corev1.SecretType
		if includeKey {
			secretData[corev1.TLSPrivateKeyKey] = ckp.KeyPem
			secretType = corev1.SecretTypeTLS
		} else {
			// can't use tls secret because we're not persisting a key
			secretType = corev1.SecretTypeOpaque
		}
		if secret == nil {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
				Type: secretType,
				Data: secretData,
			}
			_, err = kubeClient.CoreV1().Secrets(t.Namespace).Create(context.TODO(), secret,
				metav1.CreateOptions{
					FieldManager: t.FieldManager,
				})
			if err == nil {
				t.logf("Persisted new %s secret %s/%s", secretType, t.Namespace, name)
			}
			return err
		}
		secret.Type = secretType
		secret.Data = secretData
		_, err = kubeClient.CoreV1().Secrets(t.Namespace).Update(context.TODO(), secret,
			metav1.UpdateOptions{
				FieldManager: t.FieldManager,
			})
		if err == nil {
			t.logf("Updated %s secret %s/%s", secretType, t.Namespace, name)
		}
		return err
	})
}

func (t *TLSSecret) backgroundRenewal() {
	var sleepTime time.Duration
	t.logf("Starting background refresh for TLS secret %s/%s", t.Namespace, t.Name)
	for {
		if sleepTime >= 0 {
			clock.Sleep(sleepTime)
		}
		func() {
			t.lock.Lock()
			defer t.lock.Unlock()
			if sleepTime > 0 {
				_, err := t.getTLSCertificate(nil)
				if err != nil {
					t.logf("failed to renew TLS certificate %s/%s: %s", t.Namespace, t.Name, err.Error())
					sleepTime = time.Minute
					return
				}
			}
			sleepTime = time.Until(t.renewalTime) - time.Minute
		}()
	}
}

func (t *TLSSecret) Create() error {
	if err := t.validateNames(); err != nil {
		return err
	}
	_, err := t.GetCertificateKeyPair()
	return err
}

func (t *TLSSecret) Delete() error {
	if err := t.validateNames(); err != nil {
		return err
	}
	err := t.deleteSecret(t.Name)
	caName := defaultString(t.CAName, t.Name+"-ca")
	if err == nil {
		err = t.deleteSecret(caName)
	}
	if err == nil {
		err = t.deleteSecret(defaultString(t.CAPublicName, caName+"-public"))
	}
	return err
}

func (t *TLSSecret) deleteSecret(name string) error {
	kubeClient, err := t.getKubeClient()
	if err != nil {
		return err
	}
	secrets := kubeClient.CoreV1().Secrets(t.Namespace)
	err = secrets.Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err == nil {
		t.logf("Deleted secret %s/%s", t.Namespace, name)
	}
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

func getSecretData(secret *corev1.Secret, name string) []byte {
	if secret.Data == nil {
		return nil
	}
	return secret.Data[name]
}

func defaultString(s, d string) string {
	if s != "" {
		return s
	}
	return d
}
