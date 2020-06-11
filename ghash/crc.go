package ghash

import "hash/crc32"

type CRC struct {
	hash
}

func (s *CRC) Hash(data []byte) ([]byte, error) {
	h := crc32.NewIEEE()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *CRC) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
