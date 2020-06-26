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
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestTLS(t *testing.T) {
	k := fake.NewSimpleClientset()
	kt := &TLSSecret{
		ExplicitKubeClient: k,
		Name:               "tls",
	}
	tlsConfig, err := kt.GetTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil {
		t.Error()
	}
	cert, err := tlsConfig.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(cert.Certificate); n != 2 {
		t.Error(n)
	}
	if s, err := kt.getSecret("tls"); s == nil || err != nil {
		t.Error("did not generate certificate secrets", s, err)
	}
	if s, err := kt.getSecret("tls-ca"); s == nil || err != nil {
		t.Error("did not generate certificate secrets", s, err)
	}
	ckp, err := kt.GetCertificateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !ckp.IsValid(10 * time.Minute) {
		t.Error("invalid certificate generated")
	}
}
