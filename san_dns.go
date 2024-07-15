package tls_client_auth_san_dns

import (
	"strings"
	"fmt"
	"regexp"
	"crypto/x509"
	"github.com/caddyserver/certmagic"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(Verifier{})
}

type loggableRE2Array []*regexp.Regexp

func (ra loggableRE2Array) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if ra != nil { for _, r := range ra { enc.AppendString(r.String()) } }
	return nil
}

type Verifier struct {
	Names []string `json:"names,omitempty"`
	logger    *zap.Logger
	exacts    []string
	wildcards []string
	regexps   loggableRE2Array
}

func (Verifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.san_dns",
		New: func() caddy.Module { return new(Verifier) },
	}
}

func (v *Verifier) Provision(ctx caddy.Context) error {
	v.logger = ctx.Logger()
	for _, name := range v.Names {
		if strings.HasPrefix(name, "/") && strings.HasSuffix(name, "/") {
			v.regexps = append(v.regexps, regexp.MustCompile(strings.TrimSuffix(strings.TrimPrefix(name, "/"), "/")))
			continue
		}
		if strings.ContainsAny(name, "*") {
			v.wildcards = append(v.wildcards, name)
		} else {
			v.exacts = append(v.exacts, name)
		}
	}
	v.logger.Debug("provisioned", zap.Strings("exacts", v.exacts), zap.Strings("wildcards", v.wildcards), zap.Array("regexps", loggableRE2Array(v.regexps)))
	return nil
}

func (v Verifier) VerifyClientCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) < 1 { return fmt.Errorf("SAN DNS: no certificates provided") }

	var found *x509.Certificate
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			v.logger.Debug("parsing error, skipping", zap.Error(err))
			continue
		}
		if cert.KeyUsage & x509.KeyUsageCertSign != 0 { continue } // this cert is used to sign other certs, we should skip it
		if found != nil { return fmt.Errorf("SAN DNS: multiple client certificates found") }
		found = cert
	}
	if found == nil { return fmt.Errorf("SAN DNS: no client certificates found") }

	for _, name := range found.DNSNames {
		for _, exact := range v.exacts { if name == exact {
			v.logger.Debug("exact match", zap.String("client", name))
			return nil
		} }
		for _, wildcard := range v.wildcards { if certmagic.MatchWildcard(name, wildcard) {
			v.logger.Debug("wildcard match", zap.String("client", name), zap.String("wildcard", wildcard))
			return nil
		} }
		for _, re2 := range v.regexps { if re2.MatchString(name) {
			v.logger.Debug("regexp match", zap.String("client", name), zap.String("regexp", re2.String()))
			return nil
		} }
	}

	return fmt.Errorf("SAN DNS: no match for names: %v", found.DNSNames)
}
