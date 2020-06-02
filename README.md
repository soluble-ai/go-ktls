# go-ktls

A small library that will make a best-effort to get you a TLS secret when running in Kubernetes.

It tries the following things:

1. Look for `tls.crt` and `tls.key` in a directory that you configure
2. Look for the cert and key in environment variables that you configure
3. Look for a Kubernetes TLS secert
4. Generate a new CA certificate and TLS certificate and store them as Kubernetes secrets

For quick one-off things the fallback to generating a cert will just let things work as long as you have permissions, which you may well already have if you're running in a non-production cluster.  The auto-generated cert doesn't have any DNSNames set so it's enough to establish a TLS connection but not enough to verify.

In production cases it may be more common to have generated the cert in some other way and mounted it as a volume or available in environment variables.  In these cases you don't need any particular Kubernetes permissions.

A small command line utility to generate certs is also provided.
