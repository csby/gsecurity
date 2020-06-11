package grsa

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivate_FromFile(t *testing.T) {
	keyPath, err := testGetOpensslPrivateKeyFilePath()
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivate := &Private{}
	err = rsaPrivate.FromFile(keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRsa_End(t *testing.T) {
	folder := testRsaFileFolder()
	os.RemoveAll(folder)
}

func testRsaFileFolder() string {
	_, file, _, _ := runtime.Caller(0)

	return filepath.Join(filepath.Dir(file), "rsa")
}

func testGetOpensslPrivateKeyFilePath() (string, error) {
	folder := testRsaFileFolder()
	err := os.MkdirAll(folder, 0777)
	if err != nil {
		return "", err
	}

	path := filepath.Join(folder, "openssl.key")
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	key := `-----BEGIN PRIVATE KEY-----
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
fPYAR+fQru+WNRXZbDWTUNiDz7CpQKw=
-----END PRIVATE KEY-----
`

	_, err = fmt.Fprint(file, key)
	if err != nil {
		return "", err
	}

	return path, nil
}
