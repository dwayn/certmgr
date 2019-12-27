// Package cert contains certificate specifications and
// certificate-specific management.
package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"sort"
)

// Compare if hostnames in certificate and spec are equal
func CertificateMatchesHostname(hosts []string, cert *x509.Certificate) bool {
	a := make([]string, len(hosts))
	for idx := range hosts {
		// normalize the IPs.
		ip := net.ParseIP(hosts[idx])
		if ip == nil {
			a[idx] = hosts[idx]
		} else {
			a[idx] = ip.String()
		}
	}
	b := make([]string, len(cert.DNSNames), len(cert.DNSNames)+len(cert.IPAddresses))
	copy(b, cert.DNSNames)
	for idx := range cert.IPAddresses {
		b = append(b, cert.IPAddresses[idx].String())
	}

	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

func CertificateChainVerify(ca *x509.Certificate, cert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	return err
}

func EncodeKeyToPem(key interface{}) ([]byte, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: data,
			},
		), nil
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
			},
		), nil
	}
	return nil, errors.New("private key is neither ecdsa nor rsa thus cannot be encoded")
}

// encodeCertificateToPEM serialize a certificate into pem format
func EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		},
	)
}
