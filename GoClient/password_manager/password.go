package passwordmanager

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"

	"GoClient/crypto"
)

type KeyVerificationParams struct {
    Salt       []byte `json:"salt"`
	Verifier   []byte `json:"verifier"`
}

func SetPassword(path, password string) error {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return err
    }

    key := crypto.DeriveKeyFromPassphrase(password, salt)
	verifier, err := crypto.Encrypt(key, []byte("VerifierString"))
	if err != nil {
		return err
	}

    passwordHash := &KeyVerificationParams{
        Salt:       salt,
        Verifier:   verifier,
    }

    data, err := json.MarshalIndent(passwordHash, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0600)
}

func Verify(path, password string) (bool, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return false, err
    }

    var keyVerificationParams KeyVerificationParams
    if err := json.Unmarshal(data, &keyVerificationParams); err != nil {
        return false, err
    }

    key := crypto.DeriveKeyFromPassphrase(password, keyVerificationParams.Salt)
	keyCheck, err := crypto.Decrypt(key, keyVerificationParams.Verifier)
	if err != nil {
		return false, err
	}

    return subtle.ConstantTimeCompare(keyCheck, []byte("VerifierString")) == 1, nil
}

func Test() {
	password := "liam"
	SetPassword("password_manager/passwd.json", password)

	correct1, err := Verify("password_manager/passwd.json", password); if err != nil {
		fmt.Println(err)
	}
	correct2, err := Verify("password_manager/passwd.json", "hblloWorld"); if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("First Password: %t\n", correct1)
	fmt.Printf("Second Password: %t\n", correct2)
}