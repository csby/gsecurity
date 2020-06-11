package ghash

import (
	"crypto"
	"encoding/hex"
)

type Hash interface {
	Type() crypto.Hash
	Hash(data []byte) ([]byte, error)
	HashToString(data []byte) (string, error)
}

type hash struct {
}

func (s *hash) ToString(val []byte) string {
	return hex.EncodeToString(val)
}

func (s *hash) ToData(val string) ([]byte, error) {
	return hex.DecodeString(val)
}
