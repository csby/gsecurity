package ghash

import (
	"crypto"
	"crypto/sha256"
)

type Sha256 struct {
	hash
}

func (s *Sha256) Type() crypto.Hash {
	return crypto.SHA256
}

func (s *Sha256) Hash(data []byte) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Sha256) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
