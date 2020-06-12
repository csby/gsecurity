package gcrt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/csby/gsecurity/grsa"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	OidOrganization       = []int{2, 5, 4, 10}         // 证书类型 (string)
	OidOrganizationalUnit = []int{2, 5, 4, 11}         // 证书标识 (string)
	OidCommonName         = []int{2, 5, 4, 3}          // 显示名称 (string)
	OidLocality           = []int{2, 5, 4, 7}          // 地区 (string)
	OidProvince           = []int{2, 5, 4, 8}          // 省份 (string)
	OidStreetAddress      = []int{2, 5, 4, 9}          // 地址 (string)
	OidNotBefore          = []int{2, 8, 8, 6, 3, 1, 4} // 起始有效期 (time)
	OidNotAfter           = []int{2, 8, 8, 6, 3, 1, 5} // 截止有效期 (time)
)

type Crt struct {
	certificate *x509.Certificate
}

func (s *Crt) Certificate() *x509.Certificate {
	return s.certificate
}

func (s *Crt) Pool() *x509.CertPool {
	if s.certificate == nil {
		return nil
	}

	pool := x509.NewCertPool()
	pool.AddCert(s.certificate)

	return pool
}

func (s *Crt) PublicKey() *grsa.Public {
	if s.certificate == nil {
		return nil
	}
	if s.certificate.PublicKey == nil {
		return nil
	}

	key, ok := s.certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}

	return grsa.NewPublic(key)
}

func (s *Crt) Create(template, parentTemplate *x509.Certificate, publicKey *grsa.Public, privateKey *grsa.Private) error {
	data, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, publicKey.Key(), privateKey.Key())
	if err != nil {
		return err
	}

	s.certificate, err = x509.ParseCertificate(data)
	if err != nil {
		return err
	}

	return nil
}

func (s *Crt) FromCertificate(certificate *x509.Certificate) {
	s.certificate = certificate
}

func (s *Crt) FromConnectionState(state *tls.ConnectionState) {
	if state == nil {
		return
	}
	if len(state.PeerCertificates) < 1 {
		return
	}

	s.certificate = state.PeerCertificates[0]
}

func (s *Crt) FromFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return s.FromData(data)
}

func (s *Crt) FromData(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("invalid certificate file")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate file content: %v", err)
	}
	s.certificate = certificate

	return nil
}

func (s *Crt) ToFile(path string) error {
	if s.certificate == nil {
		return fmt.Errorf("invalid certificate")
	}

	folder := filepath.Dir(path)
	err := os.MkdirAll(folder, 0777)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: s.certificate.Raw})
}

func (s *Crt) ToMemory() ([]byte, error) {
	if s.certificate == nil {
		return nil, fmt.Errorf("invalid certificate")
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certificate.Raw}), nil
}

func (s *Crt) IsCa() bool {
	if s.certificate == nil {
		return false
	}

	return s.certificate.IsCA
}

func (s *Crt) Verify(ca *Crt) error {
	if ca == nil {
		return fmt.Errorf("invalid ca certificate")
	}
	if ca.certificate == nil {
		return fmt.Errorf("invalid ca certificate")
	}
	if s.certificate == nil {
		return fmt.Errorf("invalid certificate")
	}

	return s.certificate.CheckSignatureFrom(ca.certificate)
}

func (s *Crt) NotBefore() *time.Time {
	if s.certificate == nil {
		return nil
	}

	return &s.certificate.NotBefore
}

func (s *Crt) NotAfter() *time.Time {
	if s.certificate == nil {
		return nil
	}

	return &s.certificate.NotAfter
}

func (s *Crt) SerialNumber() *big.Int {
	if s.certificate == nil {
		return nil
	}

	return s.certificate.SerialNumber
}

func (s *Crt) SerialNumberString() string {
	if s.certificate == nil {
		return ""
	}

	if s.certificate.SerialNumber == nil {
		return ""
	} else {
		return s.certificate.SerialNumber.Text(16)
	}
}

func (s *Crt) CommonName() string {
	if s.certificate == nil {
		return ""
	}
	return s.certificate.Subject.CommonName
}

func (s *Crt) Organization() string {
	if s.certificate == nil {
		return ""
	}
	return s.arrayToString(s.certificate.Subject.Organization)
}

func (s *Crt) OrganizationalUnit() string {
	if s.certificate == nil {
		return ""
	}
	return s.arrayToString(s.certificate.Subject.OrganizationalUnit)
}

func (s *Crt) Locality() string {
	if s.certificate == nil {
		return ""
	}
	return s.arrayToString(s.certificate.Subject.Locality)
}

func (s *Crt) Province() string {
	if s.certificate == nil {
		return ""
	}
	return s.arrayToString(s.certificate.Subject.Province)
}

func (s *Crt) StreetAddress() string {
	if s.certificate == nil {
		return ""
	}
	return s.arrayToString(s.certificate.Subject.StreetAddress)
}

func (s *Crt) arrayToString(val []string) string {
	if len(val) > 0 {
		return strings.Join(val, "\\")
	}

	return ""
}
