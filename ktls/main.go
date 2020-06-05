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
	"flag"
	"fmt"
	"strings"

	"github.com/soluble-ai/go-ktls"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var secret = &ktls.TLSSecret{}
var quiet bool
var dnsNames string

func main() {
	flag.StringVar(&secret.CAName, "ca-name", "", "The name of the CA secret")
	flag.StringVar(&secret.Name, "name", "tls", "The name of the secret")
	flag.StringVar(&secret.Namespace, "namespace", "default", "The namespace to create the secret in")
	flag.StringVar(&dnsNames, "dns-names", "", "Comma separated list of DNS names for the cert")
	flag.BoolVar(&quiet, "q", false, "Don't print anything")
	flag.Parse()
	if dnsNames != "" {
		secret.DNSNames = strings.Split(dnsNames, ",")
	}
	if quiet {
		secret.Log = func(format string, values ...interface{}) {}
	}
	cert, err := secret.GetCertificate()
	if err != nil {
		panic(err)
	}
	if !quiet {
		fmt.Println(string(cert.CertPem))
	}
}
