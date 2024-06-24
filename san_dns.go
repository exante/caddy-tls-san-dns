package tls_client_auth_san_dns

import (
	"strings"
	"fmt"
	"crypto/x509"
	"github.com/caddyserver/certmagic"
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Verifier{})
}

type Verifier struct {
	Names []string `json:"names,omitempty"`
}

func (Verifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.san_dns",
		New: func() caddy.Module { return new(Verifier) },
	}
}

func (v Verifier) VerifyClientCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) < 1 { return fmt.Errorf("no certificates provided") }

	var found *x509.Certificate
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil { continue }
		if cert.KeyUsage & x509.KeyUsageCertSign != 0 { continue } // this cert is used to sign other certs, we should skip it
		if found != nil { return fmt.Errorf("multiple client certificates found") }
		found = cert
	}
	if found == nil { return fmt.Errorf("no client certificates found") }

	for _, name := range v.Names {
		for _, dns := range found.DNSNames {
			if strings.Contains(name, "*") {
				if certmagic.MatchWildcard(dns, name) { return nil }
			} else {
				if dns == name { return nil }
			}
		}
	}
	return fmt.Errorf("no match for SAN DNS in client certificates")
}
