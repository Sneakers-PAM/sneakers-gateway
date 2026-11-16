// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	mtls "github.com/Bugs5382/go-mtls"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// testPKI is a throwaway CA that signs leaf certificates for 127.0.0.1.
type testPKI struct {
	dir  string
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	caPE string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := &testPKI{dir: t.TempDir(), ca: ca, key: key}
	p.caPE = filepath.Join(p.dir, "ca.pem")
	writePEM(t, p.caPE, "CERTIFICATE", der)
	return p
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// leaf writes a certificate and key signed by the CA and returns the env that names them.
func (p *testPKI) leaf(t *testing.T, name string, serial int64) map[string]string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(p.dir, name+".crt")
	keyPath := filepath.Join(p.dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	return map[string]string{"MTLS_CERT_FILE": certPath, "MTLS_KEY_FILE": keyPath, "MTLS_CA_FILE": p.caPE}
}

// startMTLSVault serves the bearer vault over mutual TLS with the given server files.
func startMTLSVault(t *testing.T, env map[string]string) (string, *bearerVault) {
	t.Helper()
	prov, err := mtls.NewProvider(mtls.Files{Cert: env["MTLS_CERT_FILE"], Key: env["MTLS_KEY_FILE"], CA: env["MTLS_CA_FILE"]})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(prov.ServerOption())
	v := &bearerVault{got: make(chan string, 4)}
	vaultv1.RegisterVaultServiceServer(srv, v)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), v
}

func withToken(t *testing.T, env map[string]string) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "tok")
	env["WORKLOAD_TOKEN_FILE"] = path
	return env
}

func TestBackendClientsCallAnMTLSBackendAndStillSendTheToken(t *testing.T) {
	pki := newTestPKI(t)
	addr, v := startMTLSVault(t, pki.leaf(t, "vault", 2))
	opts, err := backendDialOptions("real", envOf(withToken(t, pki.leaf(t, "gateway", 3))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialVault(t, addr, opts).GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{}); err != nil {
		t.Fatalf("call over mutual TLS: %v", err)
	}
	if got := <-v.got; got != "Bearer tok" {
		t.Fatalf("authorization = %q, the workload token must still ride the mTLS call", got)
	}
}

func TestBackendClientsRefuseABackendSignedByAnotherCA(t *testing.T) {
	addr, _ := startMTLSVault(t, newTestPKI(t).leaf(t, "vault", 2))
	other := newTestPKI(t)
	opts, err := backendDialOptions("real", envOf(withToken(t, other.leaf(t, "gateway", 3))))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialVault(t, addr, opts).GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{}); err == nil {
		t.Fatal("a backend whose certificate is signed by another CA must be refused")
	}
}

func TestBackendClientsWithMTLSDoNotFallBackToPlaintext(t *testing.T) {
	pki := newTestPKI(t)
	addr, _ := startBearerVault(t) // plaintext server
	opts, err := backendDialOptions("real", envOf(withToken(t, pki.leaf(t, "gateway", 3))))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialVault(t, addr, opts).GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{}); err == nil {
		t.Fatal("with mutual TLS configured a plaintext backend must not be called")
	}
}

func TestLoadMTLSPlaintextWhenNothingIsSet(t *testing.T) {
	p, err := loadMTLS(envOf(nil))
	if err != nil || p != nil {
		t.Fatalf("loadMTLS = %v, %v; want nil, nil so the chart switch can roll back", p, err)
	}
}

func TestLoadMTLSRefusesAPartialSetting(t *testing.T) {
	pki := newTestPKI(t)
	env := pki.leaf(t, "gateway", 3)
	delete(env, "MTLS_KEY_FILE")
	if _, err := loadMTLS(envOf(env)); err == nil {
		t.Fatal("two of three files set must fail start-up, not silently fall back to plaintext")
	}
}

func TestLoadMTLSNamesAnUnreadableFile(t *testing.T) {
	pki := newTestPKI(t)
	env := pki.leaf(t, "gateway", 3)
	env["MTLS_CA_FILE"] = filepath.Join(t.TempDir(), "absent")
	if _, err := loadMTLS(envOf(env)); err == nil {
		t.Fatal("an unreadable file must fail start-up")
	}
}
