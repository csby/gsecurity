package ghash

import (
	"crypto"
	"crypto/md5"
)

type Md5 struct {
	hash
}

func (s *Md5) Type() crypto.Hash {
	return crypto.MD5
}

func (s *Md5) Hash(data []byte) ([]byte, error) {
	h := md5.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Md5) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
