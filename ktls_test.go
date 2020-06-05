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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestTLS(t *testing.T) {
	dir, err := ioutil.TempDir("", "go-ktls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	k := fake.NewSimpleClientset()
	kt := &TLSSecret{
		ExplicitKubeClient: k,
		Name:               "tls",
		MountPoint:         dir,
	}
	tlsConfig, err := kt.GetTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil {
		t.Error()
	}
	if n := len(tlsConfig.Certificates[0].Certificate); n != 2 {
		t.Error(n)
	}
	if s, err := kt.getSecret("tls"); s == nil || err != nil {
		t.Error("did not generate certificate secrets", s, err)
	}
	if s, err := kt.getSecret("tls-ca"); s == nil || err != nil {
		t.Error("did not generate certificate secrets", s, err)
	}
	ckp, err := kt.GetCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if !ckp.IsValid() {
		t.Error("invalid certificate generated")
	}
}

func createCert(t *testing.T) *CertificateKeyPair {
	caCert, err := GenerateCert("Test Inc", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := GenerateCert("Test Inc", nil, caCert)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestFS(t *testing.T) {
	cert := createCert(t)
	dir, err := ioutil.TempDir("", "go-ktls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := ioutil.WriteFile(filepath.Join(dir, "tls.key"), cert.KeyPem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "tls.crt"), cert.CertPem, 0600); err != nil {
		t.Fatal(err)
	}
	kt := &TLSSecret{
		MountPoint: dir,
	}
	ckp, err := kt.GetCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if !ckp.IsValid() {
		t.Error("invalid certificate")
	}
}
