package main

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os/user"
	"path"

	"github.com/dbzer0/cypher"
)

var (
	ErrPrivateKeyAlreadyExists = errors.New("private key already exists")
	ErrPublicKeyAlreadyExists  = errors.New("public key already exists")
	ErrInvalidSignature        = errors.New("invalid signature")
)

const (
	PrivateKeyPath = "acb.private"
	PublicKeyPath  = "acb.pub"
)

func PrivateKey() ([]byte, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(path.Join(usr.HomeDir, PrivateKeyPath))
	if err != nil {
		return nil, err
	}

	pk, err := cypher.PrivateKeyFromB32String(string(b[:]))
	if err != nil {
		return nil, err
	}

	return pk.ToBytes()
}

func PublicKey() ([]byte, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(path.Join(usr.HomeDir, PublicKeyPath))
	if err != nil {
		return nil, err
	}

	pk, err := cypher.PublicKeyFromB32String(string(b[:]))
	if err != nil {
		return nil, err
	}

	return pk.ToBytes(), nil
}

func GenPrivateKey() error {
	cypher.Curve = elliptic.P384

	key, err := cypher.NewPrivateKey()
	if err != nil {
		return err
	}
	str, err := key.ToB32String()
	if err != nil {
		return err
	}

	usr, err := user.Current()
	if err != nil {
		return err
	}
	keyOut := path.Join(usr.HomeDir, PrivateKeyPath)

	// проверяем существование старого ключа
	_, err = ioutil.ReadFile(keyOut)
	if err == nil {
		return ErrPrivateKeyAlreadyExists
	}

	if err := ioutil.WriteFile(keyOut, []byte(str), 0600); err != nil {
		return err
	}

	return nil
}

func GenPublicKey() error {
	usr, err := user.Current()
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(path.Join(usr.HomeDir, PublicKeyPath))
	if err == nil {
		return ErrPublicKeyAlreadyExists
	}

	// читаем приватный ключ
	b, err = ioutil.ReadFile(path.Join(usr.HomeDir, PrivateKeyPath))
	if err != nil {
		return err
	}
	pk, err := cypher.PrivateKeyFromB32String(string(b[:]))
	if err != nil {
		return err
	}

	key := pk.GetPublicKey()
	str := key.ToB32String()

	if err := ioutil.WriteFile(path.Join(usr.HomeDir, PublicKeyPath), []byte(str), 0600); err != nil {
		return err
	}

	return nil
}

type DataPayload struct {
	A    int    `json:"a"`
	B    int    `json:"b"`
	Text string `json:"text"`
}

func (d *DataPayload) ToBytes() ([]byte, error) {
	return json.Marshal(d)
}

func ValidatePayload(payloadB32 []byte) ([]byte, error) {
	publicKeyBase32, err := PublicKey()
	if err != nil {
		return nil, err
	}

	// Unmarshal the public key.
	publicKey, err := cypher.PublicKeyFromBytes(publicKeyBase32)
	if err != nil {
		return nil, err
	}

	lic, err := cypher.PayloadFromB32String(string(payloadB32))
	if err != nil {
		return nil, err
	}

	// validate the signature.
	if ok, err := lic.Verify(publicKey); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrInvalidSignature
	}

	var data DataPayload

	if err := json.Unmarshal(lic.Data, &data); err != nil {
		return nil, err
	}

	return data.ToBytes()
}

func GenPayload(payload *DataPayload) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	// читаем приватный ключ
	b, err := ioutil.ReadFile(path.Join(usr.HomeDir, PrivateKeyPath))
	if err != nil {
		return "", err
	}
	pk, err := cypher.PrivateKeyFromB32String(string(b[:]))
	if err != nil {
		return "", err
	}

	data, err := payload.ToBytes()
	if err != nil {
		return "", err
	}

	l, err := cypher.NewCryptor(pk, data)
	if err != nil {
		return "", err
	}

	return l.ToB32String()
}
