package cypher

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

func toBytes(obj interface{}) ([]byte, error) {
	var buffBin bytes.Buffer
	if err := json.NewEncoder(&buffBin).Encode(obj); err != nil {
		return nil, err
	}

	return buffBin.Bytes(), nil
}

func toB64String(obj interface{}) (string, error) {
	b, err := toBytes(obj)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func toB32String(obj interface{}) (string, error) {
	b, err := toBytes(obj)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(b), nil
}

func toHexString(obj interface{}) (string, error) {
	b, err := toBytes(obj)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func fromBytes(obj interface{}, b []byte) error {
	buffBin := bytes.NewBuffer(b)
	return json.NewDecoder(buffBin).Decode(obj)
}

func fromB64String(obj interface{}, s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return fromBytes(obj, b)
}

func fromB32String(obj interface{}, s string) error {
	b, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return fromBytes(obj, b)
}

func fromHexString(obj interface{}, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}

	return fromBytes(obj, b)
}
