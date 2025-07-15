package gocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// --- Argon2id Parameters ---
// Adjust these values based on your server's resources and desired security level.
// Higher values increase security but also computation time.
// Aim for 50-500ms for verification on your target hardware.
const (
	saltLen     = uint32(32)        // Length of the salt in bytes (recommended 16 bytes)
	memory      = uint32(64 * 1024) // Memory in KiB (e.g., 64MB). Adjust based on available RAM.
	iterations  = uint32(3)         // Number of iterations.
	parallelism = uint8(2)          // Number of CPU threads/lanes.
	keyLen      = uint32(64)        // Length of the derived key/hash output in bytes (e.g., 32 bytes for 256-bit)
	encKeyLen   = uint32(32)        // keyLen for encryption method
)

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLen      uint32
}

// generateSalt generates a cryptographically secure random salt of the specified length.
func generateSalt(n int) ([]byte, error) {
	salt := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to read random bytes for salt: %w", err)
	}
	return salt, nil
}

// FastHash hashes a string using hmac with sha512
func FastHash(data string, salt ...string) (string, error) {
	if len(salt) == 0 {
		k, err := generateSalt(256)
		if err != nil {
			return "", err
		}
		salt = append(salt, string(k))
	}

	h := hmac.New(sha512.New, []byte(salt[0]))
	h.Write([]byte(data))
	bs := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs), nil
}

// HashPasswd hashes a password with the secure Argon2 method
func HashPasswd(password string) (string, error) {
	salt, err := generateSalt(int(saltLen))
	if err != nil {
		return "", err
	}

	// The core Argon2id hashing operation
	hash := argon2.IDKey([]byte(password), salt, memory, iterations, parallelism, keyLen)

	encHash := fmt.Sprintf(
		"%s$%s$%s$%s$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
		strconv.FormatUint(uint64(memory), 10),
		strconv.FormatUint(uint64(iterations), 10),
		strconv.FormatUint(uint64(parallelism), 10),
		strconv.FormatUint(uint64(keyLen), 10),
	)

	return encHash, nil
}

// VerifyPasswd securely verifies a plaintext password against a stored Argon2id hash
func VerifyPasswd(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 { // Expecting 6 parts: salt, hash, memory, iterations, parallelism, keyLen
		return false, fmt.Errorf("malformed custom argon2id hash string: incorrect number of parts")
	}

	// Parse components from the parts
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt from hash string: %w", err)
	}
	storedDerivedKey, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode derived key (hash) from hash string: %w", err)
	}

	memory, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return false, fmt.Errorf("failed to parse memory parameter: %w", err)
	}
	iterations, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return false, fmt.Errorf("failed to parse iterations parameter: %w", err)
	}
	parallelism, err := strconv.ParseUint(parts[4], 10, 8)
	if err != nil {
		return false, fmt.Errorf("failed to parse parallelism parameter: %w", err)
	}
	keyLen, err := strconv.ParseUint(parts[5], 10, 32)
	if err != nil {
		return false, fmt.Errorf("failed to parse key length parameter: %w", err)
	}

	// Recompute the hash using the provided password and the extracted parameters/salt.
	// Crucially, the KeyLen used here must be the one stored, to ensure the output length matches.
	comparisonDerivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		uint32(memory),
		uint32(iterations),
		uint8(parallelism),
		uint32(keyLen),
	)

	// Perform a constant-time comparison to prevent timing attacks.
	return subtle.ConstantTimeCompare(comparisonDerivedKey, storedDerivedKey) == 1, nil
}

// deriveKeyFromPassphrase uses a hashing method to derive a fixed-length
// encryption key from a passphrase and a salt.
//
// @secure:
//   - true: use secure argon2
//   - false: use fast hmac with sha512
func deriveKeyFromPassphrase(passphrase string, salt []byte, secure bool, params ...argon2Params) ([]byte, error) {
	var derivedKey []byte

	if len(params) == 0 {
		params = append(params, argon2Params{
			memory:      memory,
			iterations:  iterations,
			parallelism: parallelism,
			keyLen:      encKeyLen,
		})
	}

	if secure {
		// Use argon2.IDKey to derive the key
		derivedKey = argon2.IDKey(
			[]byte(passphrase),
			salt,
			params[0].memory,
			params[0].iterations,
			params[0].parallelism,
			params[0].keyLen, // Specify the desired key length (e.g., 32 for AES-256)
		)
	} else {
		h := hmac.New(sha512.New, salt)
		h.Write([]byte(passphrase))
		bs := h.Sum(nil)

		// Truncate the 64-byte SHA-512 hash to 32 bytes for AES-256
		derivedKey = bs[:encKeyLen]
	}

	return derivedKey, nil
}

// Encrypt encrypts plaintext data using AES-256 GCM.
// It returns the ciphertext (which includes the nonce prepended) and any error.
//
// @useArgon2:
//   - true: use secure argon2 method to hash the passphrase
//   - false: use fast hmac with sha512 method to hash the passphrase
func Encrypt(plaintext, passphrase string, useArgon2 bool) (string, error) {
	salt, err := generateSalt(int(saltLen))
	if err != nil {
		return "", fmt.Errorf("failed to generate salt for key derivation: %w", err)
	}

	encKey, err := deriveKeyFromPassphrase(passphrase, salt, useArgon2)
	if err != nil {
		return "", fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// GCM provides authenticated encryption.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Never reuse a nonce with the same key. Generate a unique one for each encryption.
	nonce := make([]byte, aesGCM.NonceSize()) // NonceSize is typically 12 for AES-GCM
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal encrypts and authenticates plaintext.
	// It appends the tag to the ciphertext and prepends the nonce.
	// The additionalData is optional, used for authenticated data that is not encrypted.
	// For example, a header that needs to be integrity protected but not secret.
	// For simple encryption, we pass nil.
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil) // Nonce is prepended to ciphertext here

	alg := 0
	if useArgon2 {
		alg = 1
	}

	enc := fmt.Sprintf("%s$%s$%s$%s$%s$%s$%s",
		strconv.Itoa(alg),
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(ciphertext),
		strconv.FormatUint(uint64(memory), 10),
		strconv.FormatUint(uint64(iterations), 10),
		strconv.FormatUint(uint64(parallelism), 10),
		strconv.FormatUint(uint64(encKeyLen), 10),
	)

	return enc, nil
}

// Decrypt decrypts data encrypted with AES-256 GCM.
// It expects the ciphertext to have the nonce prepended.
func Decrypt(ciphertext, passphrase string) (string, error) {
	parts := strings.SplitN(ciphertext, "$", 7) // Split into at most 7 parts
	if len(parts) != 7 {
		return "", fmt.Errorf("malformed combined string: expected 7 parts separated by '%s', got %d", "$", len(parts))
	}

	useArgon2 := false
	if parts[0] == "1" {
		useArgon2 = true
	}

	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode salt: %w", err)
	}
	if len(salt) != int(saltLen) { // Validate salt length
		return "", fmt.Errorf("decoded salt has incorrect length: expected %d, got %d", saltLen, len(salt))
	}

	memory, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return "", fmt.Errorf("failed to parse memory parameter: %w", err)
	}
	iterations, err := strconv.ParseUint(parts[4], 10, 32)
	if err != nil {
		return "", fmt.Errorf("failed to parse iterations parameter: %w", err)
	}
	parallelism, err := strconv.ParseUint(parts[5], 10, 8)
	if err != nil {
		return "", fmt.Errorf("failed to parse parallelism parameter: %w", err)
	}
	keyLen, err := strconv.ParseUint(parts[6], 10, 32)
	if err != nil {
		return "", fmt.Errorf("failed to parse key length parameter: %w", err)
	}

	encKey, err := deriveKeyFromPassphrase(passphrase, salt, useArgon2, argon2Params{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
		keyLen:      uint32(keyLen),
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive decryption key: %w", err)
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", fmt.Errorf("ciphertext too short: not enough space for nonce")
	}

	// Extract the nonce from the beginning of the ciphertext
	nonce, encryptedMessage := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]

	// Open decrypts and authenticates ciphertext.
	// It verifies the integrity tag. If verification fails, it returns an error.
	plaintext, err := aesGCM.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt or authenticate data: %w", err)
	}

	return string(plaintext), nil
}
