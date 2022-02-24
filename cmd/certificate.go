package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

func generateCA(orgs []string) (*x509.Certificate, *rsa.PrivateKey, *bytes.Buffer, error) {
	// init CA config
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2022),
		Subject:               pkix.Name{Organization: orgs},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // expired in 10 years
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate private key for CA
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	// create the CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// CA certificate with PEM encoded
	caPEM := new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return ca, caPrivateKey, caPEM, nil
}

func signCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey, dnsNames []string, commonName string) (*bytes.Buffer, *bytes.Buffer, error) {
	// new certificate config
	newCert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(1024),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"morven.me"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // expired in 1 year
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// generate new private key
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// sign the new certificate
	newCertBytes, err := x509.CreateCertificate(rand.Reader, newCert, ca, &newPrivateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	// new certificate with PEM encoded
	newCertPEM := new(bytes.Buffer)
	_ = pem.Encode(newCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCertBytes,
	})

	// new private key with PEM encoded
	newPrivateKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(newPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(newPrivateKey),
	})

	return newCertPEM, newPrivateKeyPEM, nil
}
