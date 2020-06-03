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

package main

import (
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/soluble-ai/go-ktls"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var secret = &ktls.TLSSecret{}

func main() {
	flag.StringVar(&secret.CAName, "ca-name", "", "The name of the CA secret")
	flag.StringVar(&secret.Name, "name", "tls", "The name of the secret")
	flag.StringVar(&secret.Namespace, "namespace", "default", "The namespace to create the secret in")
	flag.Parse()
	cert, err := secret.GetCertificate()
	if err != nil {
		panic(err)
	}
	chain := cert.GetTLSCertificateChain()
	x509Cert, err := x509.ParseCertificate(chain.Certificate[0])
	if err != nil {
		panic(err)
	}
	fmt.Printf("subject=%s notAfter=%s\n", x509Cert.Subject, x509Cert.NotAfter)
}
