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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type CertificateKeyPair struct {
	KeyPem  []byte
	CertPem []byte
}

func (ckp *CertificateKeyPair) getX509Certificate() (*x509.Certificate, error) {
	block, _ := pem.Decode(ckp.CertPem)
	return x509.ParseCertificate(block.Bytes)
}

func (ckp *CertificateKeyPair) GetTLSCertificateChain() tls.Certificate {
	tlscert, err := tls.X509KeyPair(ckp.CertPem, ckp.KeyPem)
	if err != nil {
		panic(err)
	}
	return tlscert
}

func (ckp *CertificateKeyPair) getRSAPrivateKey() *rsa.PrivateKey {
	block, _ := pem.Decode(ckp.KeyPem)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key.(*rsa.PrivateKey)
}

func (ckp *CertificateKeyPair) IsValid() bool {
	if ckp == nil {
		return false
	}
	if ckp.KeyPem == nil || ckp.CertPem == nil {
		return false
	}
	cert, err := ckp.getX509Certificate()
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	return true
}

func GenerateCert(subjectOrganization string, parent *CertificateKeyPair) (*CertificateKeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{subjectOrganization},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	var parentCert *x509.Certificate
	var signingKey interface{}
	if parent == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		parentCert = &template
		signingKey = priv
	} else {
		parentCert, err = parent.getX509Certificate()
		if err != nil {
			return nil, err
		}
		signingKey = parent.getRSAPrivateKey()
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	certPem := bytes.Buffer{}
	if err = pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to encode cert: %w", err)
	}
	if parent != nil {
		certPem.WriteString("\n")
		certPem.Write(parent.CertPem)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	return &CertificateKeyPair{
		KeyPem:  keyPem,
		CertPem: certPem.Bytes(),
	}, nil
}
