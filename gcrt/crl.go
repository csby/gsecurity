package gcrt

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/csby/gsecurity/grsa"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type RevokedItem struct {
	SerialNumber       *big.Int   `json:"serialNumber" note:"证书序号"`
	RevocationTime     time.Time  `json:"revocationTime" note:"吊销时间"`
	Organization       string     `json:"organization" note:"证书类型"`
	OrganizationalUnit string     `json:"organizationalUnit" note:"证书标识"`
	CommonName         string     `json:"common_name" note:"显示名称"`
	Locality           string     `json:"locality" note:"地区"`
	Province           string     `json:"province" note:"省份"`
	StreetAddress      string     `json:"streetAddress" note:"地址"`
	NotBefore          *time.Time `json:"notBefore" note:"起始有效期"`
	NotAfter           *time.Time `json:"notAfter" note:"截止有效期"`
}

func (s RevokedItem) String() string {
	if s.SerialNumber == nil {
		return ""
	} else {
		return s.SerialNumber.Text(16)
	}
}

func (s *RevokedItem) Extensions() []pkix.Extension {
	extensions := make([]pkix.Extension, 0)
	adder := func(extension pkix.Extension) {
		extensions = append(extensions, extension)
	}

	s.addExtension(OidOrganization, s.Organization, adder)
	s.addExtension(OidOrganizationalUnit, s.OrganizationalUnit, adder)
	s.addExtension(OidCommonName, s.CommonName, adder)
	s.addExtension(OidLocality, s.Locality, adder)
	s.addExtension(OidProvince, s.Province, adder)
	s.addExtension(OidStreetAddress, s.StreetAddress, adder)
	s.addExtension(OidNotBefore, s.NotBefore, adder)
	s.addExtension(OidNotAfter, s.NotAfter, adder)

	return extensions
}

func (s *RevokedItem) addExtension(oid asn1.ObjectIdentifier, val interface{}, adder func(extension pkix.Extension)) {
	value, err := json.Marshal(val)
	if err != nil {
		return
	}

	if adder != nil {
		adder(pkix.Extension{Id: oid, Value: value})
	}
}

type RevokedInfo struct {
	ThisUpdate *time.Time    `json:"thisUpdate" note:"本次更新时间"`
	NextUpdate *time.Time    `json:"nextUpdate" note:"下次更新时间"`
	Items      []RevokedItem `json:"items" note:"证书列表"`
}

type Crl struct {
	crl *pkix.CertificateList
}

func (s *Crl) Info() (*RevokedInfo, error) {
	info := &RevokedInfo{
		Items: make([]RevokedItem, 0),
	}
	if s.crl == nil {
		return info, fmt.Errorf("invalid crl")
	}
	crl := &s.crl.TBSCertList
	info.ThisUpdate = &crl.ThisUpdate
	info.NextUpdate = &crl.NextUpdate

	lst := crl.RevokedCertificates
	lstCount := len(lst)
	for lstIndex := 0; lstIndex < lstCount; lstIndex++ {
		item := RevokedItem{
			SerialNumber:   lst[lstIndex].SerialNumber,
			RevocationTime: lst[lstIndex].RevocationTime,
		}

		extensions := lst[lstIndex].Extensions
		if len(extensions) > 0 {
			err := s.getExtension(extensions, OidOrganization, &item.Organization)
			if err != nil {
			}
			err = s.getExtension(extensions, OidOrganizationalUnit, &item.OrganizationalUnit)
			err = s.getExtension(extensions, OidCommonName, &item.CommonName)
			err = s.getExtension(extensions, OidLocality, &item.Locality)
			err = s.getExtension(extensions, OidProvince, &item.Province)
			err = s.getExtension(extensions, OidStreetAddress, &item.StreetAddress)
			err = s.getExtension(extensions, OidNotBefore, &item.NotBefore)
			err = s.getExtension(extensions, OidNotAfter, &item.NotAfter)
		}

		info.Items = append(info.Items, item)
	}

	return info, nil
}

func (s *Crl) AddCrt(crt *Crt, revocationTime *time.Time) error {
	if crt == nil {
		return fmt.Errorf("invalid crt: nil")
	}
	if crt.certificate == nil {
		return fmt.Errorf("invalid crt: internal certificate is nil")
	}
	item := &RevokedItem{
		SerialNumber:       crt.SerialNumber(),
		RevocationTime:     time.Now(),
		Organization:       crt.Organization(),
		OrganizationalUnit: crt.OrganizationalUnit(),
		CommonName:         crt.CommonName(),
		Locality:           crt.Locality(),
		Province:           crt.Province(),
		StreetAddress:      crt.StreetAddress(),
		NotBefore:          crt.NotBefore(),
		NotAfter:           crt.NotAfter(),
	}
	if revocationTime != nil {
		item.RevocationTime = *revocationTime
	}

	return s.AddItem(item)
}

func (s *Crl) AddItem(item *RevokedItem) error {
	if item == nil {
		return fmt.Errorf("parameter invalid: item is nil")
	}
	if s.crl == nil {
		s.crl = &pkix.CertificateList{
			TBSCertList: pkix.TBSCertificateList{
				RevokedCertificates: make([]pkix.RevokedCertificate, 0),
			},
		}
	}

	rc := pkix.RevokedCertificate{
		SerialNumber:   item.SerialNumber,
		RevocationTime: item.RevocationTime,
		Extensions:     item.Extensions(),
	}

	s.crl.TBSCertList.RevokedCertificates = append(s.crl.TBSCertList.RevokedCertificates, rc)
	return nil
}

func (s *Crl) FromFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return s.FromMemory(data)
}

func (s *Crl) FromMemory(data []byte) error {
	crl, err := x509.ParseCRL(data)
	if err != nil {
		return err
	}
	s.crl = crl

	return nil
}

func (s *Crl) Verify(ca *Crt) error {
	if ca == nil {
		return fmt.Errorf("invalid ca certificate")
	}
	if ca.certificate == nil {
		return fmt.Errorf("invalid ca certificate")
	}
	if s.crl == nil {
		return fmt.Errorf("invalid revocateion list")
	}

	return ca.certificate.CheckCRLSignature(s.crl)
}

func (s *Crl) ToFile(path string, caCrt *Crt, caKey *grsa.Private, thisUpdate, nextUpdate *time.Time) error {
	data, err := s.ToMemory(caCrt, caKey, thisUpdate, nextUpdate)
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

func (s *Crl) ToMemory(caCrt *Crt, caKey *grsa.Private, thisUpdate, nextUpdate *time.Time) ([]byte, error) {
	if caCrt == nil {
		return nil, fmt.Errorf("invalid ca certificate")
	}
	if caCrt.certificate == nil {
		return nil, fmt.Errorf("invalid ca certificate")
	}
	if caKey == nil {
		return nil, fmt.Errorf("invalid ca key")
	}
	if caKey.Key() == nil {
		return nil, fmt.Errorf("invalid ca key")
	}

	thisUpd := time.Now()
	if thisUpdate != nil {
		thisUpd = *thisUpdate
	}
	nextUpd := time.Now().AddDate(1, 0, 0)
	if nextUpdate != nil {
		nextUpd = *nextUpdate
	} else {
		caNotAfter := caCrt.NotAfter()
		if caNotAfter != nil {
			nextUpd = *caNotAfter
		}
	}

	if s.crl == nil {
		s.crl = &pkix.CertificateList{
			TBSCertList: pkix.TBSCertificateList{
				RevokedCertificates: make([]pkix.RevokedCertificate, 0),
			},
		}
	}

	data, err := caCrt.certificate.CreateCRL(rand.Reader, caKey.Key(), s.crl.TBSCertList.RevokedCertificates, thisUpd, nextUpd)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: data,
	}

	return pem.EncodeToMemory(block), nil
}

func (s *Crl) getExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier, v interface{}) error {
	extLen := len(extensions)
	for idx := 0; idx < extLen; idx++ {
		if extensions[idx].Id.Equal(oid) {
			err := json.Unmarshal(extensions[idx].Value, v)
			if err != nil {
				return err
			} else {
				return nil
			}
		}
	}

	return fmt.Errorf("not found")
}
