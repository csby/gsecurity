package gcrt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/csby/gsecurity/gpkcs12"
	"github.com/csby/gsecurity/grsa"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Pfx struct {
	Crt

	tlsCertificate *tls.Certificate
}

func (s *Pfx) PrivateKey() *grsa.Private {
	if s.tlsCertificate == nil {
		return nil
	}
	if s.tlsCertificate.PrivateKey == nil {
		return nil
	}

	key, ok := s.tlsCertificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil
	}

	return grsa.NewPrivate(key)
}

func (s *Pfx) PublicKey() *grsa.Public {
	privateKey := s.PrivateKey()
	if privateKey == nil {
		return nil
	}

	publicKey, err := privateKey.Public()
	if err != nil {
		return nil
	}

	return publicKey
}

func (s *Pfx) TlsCertificates() []tls.Certificate {
	if s.tlsCertificate == nil {
		return nil
	}

	return []tls.Certificate{*s.tlsCertificate}
}

func (s *Pfx) FromTlsCertificate(cert *tls.Certificate) error {
	if cert == nil {
		return fmt.Errorf("invalid tls certificate: nil")
	}
	s.tlsCertificate = cert

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	s.certificate = x509Cert

	return nil
}

func (s *Pfx) FromFile(filePath, password string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	return s.FromMemory(data, password)
}

func (s *Pfx) FromMemory(data []byte, password string) error {
	certBlocks, err := gpkcs12.ToPEM(data, password)
	if err != nil {
		return err
	}

	blockData := make([]byte, 0)
	for _, b := range certBlocks {
		blockData = append(blockData, pem.EncodeToMemory(b)...)
	}

	cert, err := tls.X509KeyPair(blockData, blockData)
	if err != nil {
		return err
	}
	s.tlsCertificate = &cert

	s.certificate, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("generate x509 certificate fail: %v", err)
	}

	return nil
}

func (s *Pfx) ToFile(path string, ca *Crt, privateKey *grsa.Private, password string) error {
	data, err := s.ToMemory(ca, privateKey, password)
	if err != nil {
		return err
	}

	folder := filepath.Dir(path)
	err = os.MkdirAll(folder, 0777)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)

	return err
}

func (s *Pfx) ToMemory(ca *Crt, privateKey *grsa.Private, password string) ([]byte, error) {
	if s.certificate == nil {
		return nil, fmt.Errorf("invalid certificate")
	}

	return gpkcs12.Encode(rand.Reader, privateKey.Key(), s.certificate, []*x509.Certificate{ca.certificate}, password)
}
