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

	"github.com/soluble-ai/go-ktls"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
)

var secret = &ktls.TLSSecret{}

func main() {
	flag.StringVar(&secret.CAName, "ca-name", "", "The name of the CA secret")
	flag.StringVar(&secret.Name, "name", "tls", "The name of the secret")
	flag.StringVar(&secret.Namespace, "namespace", "default", "The namespace to create the secret in")
	flag.StringVar(&secret.SubjectOrganization, "organization", "", "The subject organization name of the generated certificates")
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	flag.StringVar(&rules.ExplicitPath, "kube-config", "", "The kubernetes config file, required for out-of-cluster")
	flag.Parse()
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		panic(err)
	}
	secret.KubeClient = kubernetes.NewForConfigOrDie(config)
	_, err = secret.GetCertificate()
	if err != nil {
		panic(err)
	}
}
