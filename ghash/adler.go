package ghash

import "hash/adler32"

type Adler struct {
	hash
}

func (s *Adler) Hash(data []byte) ([]byte, error) {
	h := adler32.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Adler) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
