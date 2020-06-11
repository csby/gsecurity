package gaes

import "testing"

func TestAes_Encrypt(t *testing.T) {
	aes := &Aes{
		Key:       "pwd",
		Algorithm: "AES-128-CBC",
	}

	rawData := "HelloData"
	encData, err := aes.Encrypt([]byte(rawData))
	if err != nil {
		t.Fatal(err)
	}
	decData, err := aes.Decrypt(encData)
	if err != nil {
		t.Fatal(err)
	}
	if rawData != string(decData) {
		t.Errorf("rawData=%s, decData=%s", rawData, string(decData))
	}
}
