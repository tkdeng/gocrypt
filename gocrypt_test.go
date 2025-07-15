package gocrypt

import (
	"bytes"
	"testing"
)

func Test(t *testing.T) {
	salts := [][]byte{}

	for range 10000 {
		salt, err := GenerateSalt(8)
		if err != nil {
			t.Errorf("GenerateSalt failed: %v", err)
		}

		for _, s := range salts {
			if bytes.Equal(salt, s) {
				t.Errorf("GenerateSalt should return unique salts, found duplicate after %d tries", len(salts))
				return
			}
		}

		salts = append(salts, salt)
	}
}

func TestHash(t *testing.T) {
	var msg = "Hello, World!"

	hash, err := FastHash(msg)
	if err != nil {
		t.Errorf("FastHash failed: %v", err)
	}

	hash2, err := FastHash(msg)
	if err != nil {
		t.Errorf("FastHash failed: %v", err)
	}

	if hash == hash2 {
		t.Errorf("FastHash should return different hashes for the same input with different salts")
	}

	hash, err = FastHash(msg, "my_salt")
	if err != nil {
		t.Errorf("FastHash failed: %v", err)
	}

	hash2, err = FastHash(msg, "my_salt")
	if err != nil {
		t.Errorf("FastHash failed: %v", err)
	}

	if hash != hash2 {
		t.Errorf("FastHash should return the same hash for the same input and salt")
	}
}

func TestPasswd(t *testing.T) {
	var password = "my_secure_password"

	hash, err := HashPasswd(password)
	if err != nil {
		t.Errorf("HashPasswd failed: %v", err)
	}

	hash2, err := HashPasswd(password)
	if err != nil {
		t.Errorf("HashPasswd failed: %v", err)
	}

	if hash == hash2 {
		t.Errorf("HashPasswd should return different hashes for the same input with different salts")
	}

	ok, err := VerifyPasswd(password, hash)
	if err != nil {
		t.Errorf("VerifyPasswd failed: %v", err)
	}
	if !ok {
		t.Errorf("VerifyPasswd should return true for the correct password")
	}

	ok, err = VerifyPasswd("wrong_password", hash)
	if err != nil {
		t.Errorf("VerifyPasswd failed: %v", err)
	}
	if ok {
		t.Errorf("VerifyPasswd should return false for an incorrect password")
	}
}

func TestSecureEncrypt(t *testing.T) {
	var msg = "Hello, World!"
	var password = "my_secure_password"

	enc, err := Encrypt(msg, password, true)
	if err != nil {
		t.Errorf("Secure Encrypt failed: %v", err)
	}

	dec, err := Decrypt(enc, password)
	if err != nil {
		t.Errorf("Secure Decrypt failed: %v", err)
	}

	if dec != msg {
		t.Errorf("Secure Decrypt should return the original message, got: %s", dec)
	}

	// Test decryption with wrong password
	_, err = Decrypt(enc, "wrong_password")
	if err == nil {
		t.Error("Secure Decrypt should fail with an incorrect password")
	}
}

func TestFastEncrypt(t *testing.T) {
	var msg = "Hello, World!"
	var password = "my_secure_password"

	enc, err := Encrypt(msg, password, false)
	if err != nil {
		t.Errorf("Fast Encrypt failed: %v", err)
	}

	dec, err := Decrypt(enc, password)
	if err != nil {
		t.Errorf("Fast Decrypt failed: %v", err)
	}

	if dec != msg {
		t.Errorf("Fast Decrypt should return the original message, got: %s", dec)
	}

	// Test decryption with wrong password
	_, err = Decrypt(enc, "wrong_password")
	if err == nil {
		t.Error("Fast Decrypt should fail with an incorrect password")
	}
}
