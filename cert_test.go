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
)

func TestGenerateCerts(t *testing.T) {
	cackp, err := GenerateCert("Test Inc", nil, nil, 1*time.Hour)
	if err != nil {
		t.Error(err)
	}
	if !cackp.IsValid(10 * time.Minute) {
		t.Error("generated cert isn't valid")
	}
	cacert, err := cackp.GetParsedCertificate()
	if err != nil {
		t.Error(err)
	}
	if !cacert.IsCA {
		t.Error("cert is not a CA cert")
	}
	ckp, err := GenerateCert("Test Inc", nil, cackp, 1*time.Hour)
	if err != nil {
		t.Error(err)
	}
	cert := ckp.GetTLSCertificateChain()
	if len(cert.Certificate) != 2 {
		t.Errorf("expecting 2 certs in chain, not %d", len(cert.Certificate))
	}
	if b := ckp.GetCACertPem(); b == nil {
		t.Error("could not get CA cert pem")
	}
}

func TestRenewal(t *testing.T) {
	cackp, err := GenerateCert("Test Inc", nil, nil, time.Minute)
	if err != nil {
		t.Error(err)
	}
	if cackp.IsValid(2 * time.Minute) {
		t.Error("certificate should require renewal")
	}
}
