package binassets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Encrypt data with the given key
func Encrypt(key []byte, data []byte) (output []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}
	ciphertext := make([]byte, aes.BlockSize+len(data), aes.BlockSize+len(data)+sha256.Size)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	ciphertext = append(ciphertext, mac.Sum(nil)...)
	output = ciphertext
	return
}

// Decrypt and validate data with the given key
func Decrypt(key []byte, data []byte) (output []byte, err error) {
	if len(data) < (aes.BlockSize*2+sha256.Size) || (len(data)-sha256.Size)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid data length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data[:len(data)-sha256.Size])
	expectedMac := mac.Sum(nil)
	if !hmac.Equal(expectedMac, data[len(data)-sha256.Size:]) {
		return nil, errors.New("Invalid HMAC")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize : len(data)-sha256.Size]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext[:len(ciphertext)-int(ciphertext[len(ciphertext)-1])], nil
}
