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
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/soluble-ai/go-ktls"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var (
	secret = &ktls.TLSSecret{
		FieldManager: "ktls",
	}
	quiet bool
)

func envDefault(n, d string) string {
	v := os.Getenv(n)
	if v != "" {
		return v
	}
	return v
}

func addFlags(flags *pflag.FlagSet) {
	flags.StringVar(&secret.CAName, "ca-name", "", "The name of the CA secret, defaults to <name>-ca")
	flags.StringVar(&secret.Name, "name", envDefault("KTLS_NAME", ""), "The name of the secret, required")
	flags.StringVar(&secret.Namespace, "namespace", envDefault("KTLS_NAMESPACE", ""), "The namespace to create the secret in, required")
	flags.StringVar(&secret.ClusterDomainName, "cluster-domain-name", envDefault("KTSL_CLUSTER_DOMAIN_NAME", "cluster.local"),
		"The cluster domain name")
}

func complete() error {
	if secret.Namespace == "" {
		return fmt.Errorf("the --namespace flag is required")
	}
	if secret.Name == "" {
		return fmt.Errorf("the --name flag is required")
	}
	return nil
}

func deleteCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "delete",
		Short: "Delete TLS secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := complete(); err != nil {
				return err
			}
			return secret.Delete()
		},
	}
	addFlags(c.Flags())
	return c
}

func createCommand() *cobra.Command {
	var (
		dnsNames        string
		createNamespace bool
		days            int
	)
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new TLS secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := complete(); err != nil {
				return err
			}
			if dnsNames != "" {
				secret.DNSNames = strings.Split(dnsNames, ",")
			}
			secret.Duration = time.Duration(days*24) * time.Hour
			if createNamespace {
				kubeClient, err := ktls.GetDefaultKubeClient()
				if err != nil {
					return err
				}
				_, err = kubeClient.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: secret.Namespace,
					},
				}, metav1.CreateOptions{
					FieldManager: secret.FieldManager,
				})
				if err != nil && !errors.IsAlreadyExists(err) {
					return err
				}
				if err == nil {
					log.Printf("Created namespace %s", secret.Namespace)
				}
			}
			return secret.Create()
		},
	}
	flags := c.Flags()
	flags.StringVar(&dnsNames, "dns-names", "", "Comma separated list of DNS names for the cert")
	flags.BoolVar(&createNamespace, "create-namespace",
		envDefault("KTLS_CREATE_NAMESPACE", "") == "true", "Create the namespace if it doesn't already exist")
	flags.IntVar(&days, "days", 365, "Make the cert valid for this number of days")
	addFlags(flags)
	return c
}

func patchCABundleCommand() *cobra.Command {
	var (
		resource     string
		resourceName string
	)
	c := &cobra.Command{
		Use:   "patch-ca-bundle",
		Short: "Update the caBundle property on a webhook or api service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := complete(); err != nil {
				return err
			}
			restConfig, err := ktls.GetDefaultRESTConfig()
			if err != nil {
				return err
			}
			discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
			if err != nil {
				return err
			}
			gvr, err := getPatchGroupVersionResource(discoveryClient, resource)
			if err != nil {
				return err
			}
			client, err := dynamic.NewForConfig(restConfig)
			if err != nil {
				return err
			}
			var path string
			switch resource {
			case "mutatingwebhookconfigurations":
				fallthrough
			case "validatingwebhookconfigurations":
				path = "/webhooks/0/clientConfig/caBundle"
			case "apiservices":
				path = "/spec/caBundle"
			default:
				return fmt.Errorf("unknown resource %s", resource)
			}
			ckp, err := secret.GetCertificateKeyPair()
			if err != nil {
				return err
			}
			caBundle := base64.StdEncoding.EncodeToString(ckp.GetCACertPem())
			patch := fmt.Sprintf(`[{"op":"add","path":"%s","value":"%s"}]`, path, caBundle)
			_, err = client.Resource(gvr).Patch(context.TODO(), resourceName, types.JSONPatchType, []byte(patch),
				metav1.PatchOptions{
					FieldManager: "ktls",
				})
			if err == nil {
				log.Printf("Patched CA bundle into %s %s", gvr, resourceName)
			}
			return err
		},
	}
	flags := c.Flags()
	flags.StringVar(&resource, "resource", "", "The resource to patch")
	flags.StringVar(&resourceName, "resource-name", "", "The name of the resource to patch")
	addFlags(flags)
	return c
}

func getPatchGroupVersionResource(discoveryClient discovery.DiscoveryInterface, resource string) (gvr schema.GroupVersionResource, err error) {
	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return
	}
	apiResourceLists = discovery.FilteredBy(discovery.ResourcePredicateFunc(func(groupVersion string, r *metav1.APIResource) bool {
		if r.Name != resource {
			return false
		}
		for _, v := range r.Verbs {
			if v == "patch" {
				return true
			}
		}
		return false
	}), apiResourceLists)
	if len(apiResourceLists) == 0 || len(apiResourceLists[0].APIResources) == 0 {
		err = fmt.Errorf("cannot find patchable resource %s", resource)
		return
	}
	apiResources := apiResourceLists[0]
	apiResource := apiResources.APIResources[0]
	gv, _ := schema.ParseGroupVersion(apiResources.GroupVersion)
	gvr = gv.WithResource(apiResource.Name)
	return
}

func main() {
	root := cobra.Command{
		Use: "ktls",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if quiet {
				secret.Log = func(format string, values ...interface{}) {}
			}
		},
		SilenceUsage: true,
	}
	flags := root.PersistentFlags()
	flags.BoolVar(&quiet, "q", false, "Don't print anything")
	root.AddCommand(deleteCommand())
	root.AddCommand(createCommand())
	root.AddCommand(patchCABundleCommand())
	err := root.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
