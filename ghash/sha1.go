package ghash

import (
	"crypto"
	"crypto/sha1"
)

type Sha1 struct {
	hash
}

func (s *Sha1) Type() crypto.Hash {
	return crypto.SHA1
}

func (s *Sha1) Hash(data []byte) ([]byte, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Sha1) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
