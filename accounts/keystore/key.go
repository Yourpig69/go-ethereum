package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/scrypt"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	keyFile      = "encrypted_keys.txt"
	scryptN      = 16384
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	hmacKeyLen   = 32
)

func generateAnonymousPrivateKey() (*ecdsa.PrivateKey, error) {
	// Genera una chiave privata in modo anonimo utilizzando crypto/rand
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func deriveAnonymousKey() ([]byte, error) {
	// Genera una chiave di firma anonima
	signatureKey, err := generateAnonymousSignatureKey()
	if err != nil {
		return nil, err
	}

	// Genera un sale casuale per la derivazione
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Utilizza scrypt per derivare una chiave dalla passphrase anonima
	derivedKey, err := scrypt.Key([]byte("passphrase"), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	// Autentica la chiave derivata utilizzando una firma HMAC
	mac := hmac.New(sha256.New, signatureKey)
	mac.Write(derivedKey)
	authenticatedDerivedKey := mac.Sum(nil)

	return authenticatedDerivedKey, nil
}

func generateAnonymousSignatureKey() ([]byte, error) {
	// Genera una chiave di firma in modo anonimo utilizzando crypto/rand
	signatureKey := make([]byte, hmacKeyLen)
	if _, err := io.ReadFull(rand.Reader, signatureKey); err != nil {
		return nil, err
	}

	return signatureKey, nil
}

func encryptPrivateKey(privateKey, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(privateKey))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], privateKey)

	return ciphertext, nil
}

func saveKeysToFile(filename string, ciphertext, key []byte) error {
	// Concatena la chiave privata cifrata e la chiave derivata
	data := append(ciphertext, key...)

	// Scrive i dati su file
	err := ioutil.WriteFile(filename, data, 0600)
	if err != nil {
		return err
	}

	fmt.Printf("Chiavi salvate con successo nel file: %s\n", filename)
	return nil
}

func main() {
	// Genera una nuova chiave privata Ethereum in modo anonimo
	privateKey, err := generateAnonymousPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Deriva una chiave segreta in modo anonimo
	derivedKey, err := deriveAnonymousKey()
	if err != nil {
		log.Fatal(err)
	}

	// Cifra la chiave privata utilizzando la chiave segreta anonima
	ciphertext, err := encryptPrivateKey(privateKey.D.Bytes(), derivedKey)
	if err != nil {
		log.Fatal(err)
	}

	// Salva la chiave privata cifrata e la chiave segreta anonima su file in modo anonimo
	err = saveKeysToFile(keyFile, ciphertext, derivedKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("La chiave privata è stata generata, cifrata e salvata in modo anonimo.")
}
