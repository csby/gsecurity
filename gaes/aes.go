package gaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

type Aes struct {
	Key       string
	Algorithm string // AES-128-CBC、AES-192-CBC、AES-256-CBC
}

// 加密数据
// 数据返回：|block1|block2|...|blockN|
// block1为"Salted__"+salt， blockN为经PKCS5补齐数据
func (s *Aes) Encrypt(data []byte) ([]byte, error) {
	keySize := 0
	if strings.ToUpper(s.Algorithm) == strings.ToUpper("AES-128-CBC") {
		keySize = 128
	} else if strings.ToUpper(s.Algorithm) == strings.ToUpper("AES-192-CBC") {
		keySize = 192
	} else if strings.ToUpper(s.Algorithm) == strings.ToUpper("AES-256-CBC") {
		keySize = 256
	} else {
		return nil, fmt.Errorf("not support algorithm: %s", s.Algorithm)
	}

	// openssl for key and iv
	// ========================================================
	// AES-128
	// Key = MD5(password + salt)
	// IV = MD5(Key + password + salt)
	// ---------------------------------------
	// AES-256
	// Hash0 = ''
	// Hash1 = MD5(Hash0 + Password + Salt)
	// Hash2 = MD5(Hash1 + Password + Salt)
	// Hash3 = MD5(Hash2 + Password + Salt)
	// Hash4 = MD5(Hash3 + Password + Salt)
	// ...
	// Key = Hash1 + Hash2
	// IV = Hash3 + Hash4
	salt := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	passwordBytes := []byte(s.Key)
	keyVector := append(passwordBytes, salt...)
	hv, err := s.hash(keyVector)
	if err != nil {
		return nil, err
	}
	cipherKey := append(hv)
	keyLength := keySize / 8
	for {
		if len(cipherKey) >= keyLength+16 {
			break
		}

		hv = append(hv, keyVector...)
		hv, err = s.hash(hv)
		if err != nil {
			return nil, err
		}
		cipherKey = append(cipherKey, hv...)
	}
	key := cipherKey[:keyLength]
	iv := cipherKey[keyLength : keyLength+16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddingData := s.pkcs5Padding(data, aes.BlockSize)
	salted := []byte("Salted__")
	dataEncrypted := make([]byte, len(salted)+len(salt)+len(paddingData))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dataEncrypted[len(salted)+len(salt):], paddingData)

	copy(dataEncrypted, salted)
	copy(dataEncrypted[len(salted):], salt)

	return dataEncrypted, nil
}

// 解密数据
// 输入data: |block1|block2|...|blockN|
// block1：为"Salted__"+salt
// blockN：PKCS5补齐
func (s *Aes) Decrypt(data []byte) ([]byte, error) {
	keySize := 0
	if strings.ToUpper(s.Algorithm) == strings.ToUpper("AES-128-CBC") {
		keySize = 128
	} else if strings.ToUpper(s.Algorithm) == strings.ToUpper("AES-192-CBC") {
		keySize = 192
	} else if strings.ToUpper(s.Algorithm) == strings.ToUpper("AES-256-CBC") {
		keySize = 256
	} else {
		return nil, fmt.Errorf("not support algorithm: %s", s.Algorithm)
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES解密失败：数据长度与密码不匹配")
	}

	// openssl for key and iv
	// ========================================================
	// AES-128
	// Key = MD5(password + salt)
	// IV = MD5(Key + password + salt)
	// ---------------------------------------
	// AES-256
	// Hash0 = ''
	// Hash1 = MD5(Hash0 + Password + Salt)
	// Hash2 = MD5(Hash1 + Password + Salt)
	// Hash3 = MD5(Hash2 + Password + Salt)
	// Hash4 = MD5(Hash3 + Password + Salt)
	// ...
	// Key = Hash1 + Hash2
	// IV = Hash3 + Hash4

	salt := make([]byte, 0)
	if len(data) > 16 {
		sameCount := 0
		salted := []byte("Salted__")
		for index := 0; index < 8; index++ {
			if data[index] != salted[index] {
				break
			}

			sameCount++
		}

		if sameCount == 8 {
			saltData := data[8:16]
			salt = append(saltData)
		}
	}

	passwordBytes := []byte(s.Key)
	keyVector := append(passwordBytes, salt...)
	hv, err := s.hash(keyVector)
	if err != nil {
		return nil, err
	}
	cipherKey := append(hv)
	keyLength := keySize / 8
	for {
		if len(cipherKey) >= keyLength+16 {
			break
		}

		hv = append(hv, keyVector...)
		hv, err = s.hash(hv)
		if err != nil {
			return nil, err
		}
		cipherKey = append(cipherKey, hv...)
	}
	key := cipherKey[:keyLength]
	iv := cipherKey[keyLength : keyLength+16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dataDecrypted := make([]byte, len(data)-len(iv))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dataDecrypted, data[len(iv):])

	unPaddingData := s.pkcs5UnPadding(dataDecrypted)

	return unPaddingData, nil
}

// 数据添加补齐
// 源数据：					|blk12345|blk12345|blk123|
// 则在后面补齐值为2的2个字节： 	|blk12345|blk12345|blk12322|
// 源数据：					|blk12345|blk12345|blk1|
// 则在后面补齐值为4的4个字节： 	|blk12345|blk12345|blk14444|
// 源数据：					|blk12345|blk12345|blk12345|
// 则在后面补齐值为8的8个字节： 	|blk12345|blk12345|blk12345|88888888|
func (s *Aes) pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	text := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(src, text...)
}

// 数据去除补齐
// 最后一位表示补齐时添加的字节数
func (s *Aes) pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	padding := int(src[length-1])

	return src[:(length - padding)]
}

// 计算MD5哈希值
func (s *Aes) hash(data []byte) ([]byte, error) {
	h := md5.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
