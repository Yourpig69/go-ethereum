// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/scrypt"
)

const (
	keyFile        = "encrypted_keys.txt"
	scryptN        = 16384
	scryptR        = 8
	scryptP        = 1
	scryptKeyLen   = 32
	bcryptCost     = 14
	hmacKeyLen     = 32
)

var (
	hostFlag = &cli.StringFlag{
		Name:  "ip",
		Usage: "IP address of the node",
		Value: "127.0.0.1",
	}
	tcpPortFlag = &cli.IntFlag{
		Name:  "tcp",
		Usage: "TCP port of the node",
		Value: 30303,
	}
	udpPortFlag = &cli.IntFlag{
		Name:  "udp",
		Usage: "UDP port of the node",
		Value: 30303,
	}
)

var (
	keyCommand = &cli.Command{
		Name:  "key",
		Usage: "Operations on node keys",
		Subcommands: []*cli.Command{
			keyGenerateCommand,
			keyToIDCommand,
			keyToNodeCommand,
			keyToRecordCommand,
		},
	}

	keyGenerateCommand = &cli.Command{
		Name:      "generate",
		Usage:     "Generates node key files",
		ArgsUsage: "keyfile",
		Action:    generateKey,
	}

	keyToIDCommand = &cli.Command{
		Name:      "to-id",
		Usage:     "Creates a node ID from a node key file",
		ArgsUsage: "keyfile",
		Action:    keyToID,
		Flags:     []cli.Flag{},
	}

	keyToNodeCommand = &cli.Command{
		Name:      "to-enode",
		Usage:     "Creates an enode URL from a node key file",
		ArgsUsage: "keyfile",
		Action:    keyToURL,
		Flags:     []cli.Flag{hostFlag, tcpPortFlag, udpPortFlag},
	}

	keyToRecordCommand = &cli.Command{
		Name:      "to-enr",
		Usage:     "Creates an ENR from a node key file",
		ArgsUsage: "keyfile",
		Action:    keyToRecord,
		Flags:     []cli.Flag{hostFlag, tcpPortFlag, udpPortFlag},
	}
)

func generateKey(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return errors.New("need key file as argument")
	}
	file := ctx.Args().Get(0)

	passphrase := promptForPassphrase()

	key, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("could not generate key: %v", err)
	}

	derivedKey, err := deriveKeyFromPassphrase(passphrase)
	if err != nil {
		return err
	}

	ciphertext, err := encryptPrivateKey(key.D.Bytes(), derivedKey)
	if err != nil {
		return err
	}

	err = saveKeysToFile(file, ciphertext, derivedKey)
	if err != nil {
		return err
	}

	fmt.Println("Key generated, encrypted, and saved successfully.")
	return nil
}

func promptForPassphrase() string {
	fmt.Print("Enter passphrase: ")
	var passphrase string
	fmt.Scan(&passphrase)
	return passphrase
}

func keyToID(ctx *cli.Context) error {
	node, err := makeNode(ctx)
	if err != nil {
		return err
	}
	fmt.Println(node.ID())
	return nil
}

func keyToURL(ctx *cli.Context) error {
	node, err := makeNode(ctx)
	if err != nil {
		return err
	}
	fmt.Println(node.URLv4())
	return nil
}

func keyToRecord(ctx *cli.Context) error {
	node, err := makeNode(ctx)
	if err != nil {
		return err
	}
	fmt.Println(node.String())
	return nil
}

func makeNode(ctx *cli.Context) (*enode.Node, error) {
	if ctx.NArg() != 1 {
		return nil, errors.New("need key file as argument")
	}

	var (
		file = ctx.Args().Get(0)
		host = ctx.String(hostFlag.Name)
		tcp  = ctx.Int(tcpPortFlag.Name)
		udp  = ctx.Int(udpPortFlag.Name)
	)

	passphrase := promptForPassphrase()
	derivedKey, err := deriveKeyFromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}

	ciphertext, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	privateKey, err := decryptPrivateKey(ciphertext[:aes.BlockSize], derivedKey)
	if err != nil {
		return nil, err
	}

	key, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return nil, err
	}

	var r enr.Record
	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", host)
		}
		r.Set(enr.IP(ip))
	}
	if udp != 0 {
		r.Set(enr.UDP(udp))
	}
	if tcp != 0 {
		r.Set(enr.TCP(tcp))
	}

	if err := enode.SignV4(&r, key); err != nil {
		return nil, err
	}
	return enode.New(enode.ValidSchemes, &r)
}

func deriveKeyFromPassphrase(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Utilizza scrypt per derivare una chiave dalla passphrase
	derivedKey, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	return derivedKey, nil
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

func decryptPrivateKey(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Estrae l'IV dalla testa del ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Decifra la chiave privata utilizzando la chiave e l'IV
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

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

	fmt.Printf("Keys saved successfully to file: %s\n", filename)
	return nil
}

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			keyCommand,
			// Aggiungi altri comandi se necessario
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
