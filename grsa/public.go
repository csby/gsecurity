package grsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/csby/gsecurity/ghash"
	"os"
	"path/filepath"
)

type Public struct {
	key *rsa.PublicKey
}

func NewPublic(key *rsa.PublicKey) *Public {
	return &Public{key: key}
}

func (s *Public) Key() *rsa.PublicKey {
	return s.key
}

func (s *Public) Length() int {
	if s.key == nil {
		return 0
	}

	return s.key.N.BitLen()
}

func (s *Public) Base64() string {
	data, err := x509.MarshalPKIXPublicKey(s.key)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(data)
}

func (s *Public) Encrypt(data []byte) ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("invalid key")
	}

	var buf bytes.Buffer
	maxSize := s.key.N.BitLen()/8 - 11
	dataLength := len(data)
	count := dataLength / maxSize
	offset := 0
	for index := 1; index <= count; index++ {
		vav, err := rsa.EncryptPKCS1v15(rand.Reader, s.key, data[offset:offset+maxSize])
		if err != nil {
			return nil, err
		}

		_, err = buf.Write(vav)
		if err != nil {
			return nil, err
		}

		offset += maxSize
	}

	if dataLength > offset {
		vav, err := rsa.EncryptPKCS1v15(rand.Reader, s.key, data[offset:dataLength])
		if err != nil {
			return nil, err
		}

		_, err = buf.Write(vav)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (s *Public) Verify(data []byte, signature []byte, h ghash.Hash) error {
	if h == nil {
		h = &ghash.Md5{}
	}
	hashed, err := h.Hash(data)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(s.key, h.Type(), hashed, signature)
}

func (s *Public) FromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fileSize := fileInfo.Size()
	if fileSize <= 0 {
		return fmt.Errorf("invalid file")
	}

	buf := make([]byte, fileSize)
	num, err := file.Read(buf)
	if err != nil {
		return err
	} else if num <= 0 {
		return fmt.Errorf("read file fail")
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return fmt.Errorf("invalid file")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid file")
	}
	s.key = publicKey

	return nil
}

func (s *Public) ToMemory() ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("invalid key")
	}

	data, err := x509.MarshalPKIXPublicKey(s.key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}

	return pem.EncodeToMemory(block), nil
}

func (s *Public) ToFile(path string) error {
	if s.key == nil {
		return fmt.Errorf("invalid key")
	}

	data, err := x509.MarshalPKIXPublicKey(s.key)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
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

	return pem.Encode(file, block)
}
