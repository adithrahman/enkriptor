package endekrip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

// GenerateRSAKeys generates a new RSA private and public key pair
func GenerateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// SaveRSAPrivateKey saves an RSA private key to a PEM file
func SaveRSAPrivateKey(filePath string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(filePath, keyPEM, 0600)
}

// SaveRSAPublicKey saves an RSA public key to a PEM file
func SaveRSAPublicKey(filePath string, key *rsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(filePath, keyPEM, 0644)
}

// LoadRSAPrivateKey loads an RSA private key from a PEM file
func LoadRSAPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadRSAPublicKey loads an RSA public key from a PEM file
func LoadRSAPublicKey(filePath string) (*rsa.PublicKey, error) {
	keyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("not an RSA public key")
	}
}

// PKCS7Padding pads plaintext to be a multiple of the block size
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS7UnPadding removes the padding from the decrypted data
func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding size")
	}
	return data[:(length - unpadding)], nil
}

// EncryptAES encrypts data using AES-256
func EncryptAES(plainText, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plainText = PKCS7Padding(plainText, block.BlockSize())
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptAES decrypts data using AES-256
func DecryptAES(cipherText string, key []byte) ([]byte, error) {
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTextBytes) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]

	if len(cipherTextBytes)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherTextBytes, cipherTextBytes)

	return PKCS7UnPadding(cipherTextBytes)
}

// EncryptRSA encrypts data using RSA public key
func EncryptRSA(plainText []byte, pubKey *rsa.PublicKey) (string, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plainText, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptRSA decrypts data using RSA private key
func DecryptRSA(cipherText string, privKey *rsa.PrivateKey) ([]byte, error) {
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherTextBytes, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// ParseRSAPublicKeyFromPemStr parses PEM encoded RSA public key
func ParseRSAPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("not an RSA public key")
	}
}

// ParseRSAPrivateKeyFromPemStr parses PEM encoded RSA private key
func ParseRSAPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
