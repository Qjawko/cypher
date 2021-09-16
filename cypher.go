package cypher

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type Cryptor struct {
	Data []byte
	R    *big.Int
	S    *big.Int
}

func NewCryptor(k *PrivateKey, data []byte) (*Cryptor, error) {
	c := &Cryptor{
		Data: data,
	}

	if h, err := c.hash(); err != nil {
		return nil, err
	} else if r, s, err := ecdsa.Sign(rand.Reader, k.toEcdsa(), h); err != nil {
		return nil, err
	} else {
		c.R = r
		c.S = s
	}
	return c, nil
}

func (c *Cryptor) hash() ([]byte, error) {
	h256 := sha256.New()

	if _, err := h256.Write(c.Data); err != nil {
		return nil, err
	}
	return h256.Sum(nil), nil
}

func (c *Cryptor) Verify(k *PublicKey) (bool, error) {
	h, err := c.hash()
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(k.toEcdsa(), h, c.R, c.S), nil
}

func (c *Cryptor) ToBytes() ([]byte, error) {
	return toBytes(c)
}

func (c *Cryptor) ToB64String() (string, error) {
	return toB64String(c)
}

func (c *Cryptor) ToB32String() (string, error) {
	return toB32String(c)
}

func (c *Cryptor) ToHexString() (string, error) {
	return toHexString(c)
}

func PayloadFromBytes(b []byte) (*Cryptor, error) {
	l := &Cryptor{}
	return l, fromBytes(l, b)
}

func PayloadFromB64String(str string) (*Cryptor, error) {
	l := &Cryptor{}
	return l, fromB64String(l, str)
}

func PayloadFromB32String(str string) (*Cryptor, error) {
	l := &Cryptor{}
	return l, fromB32String(l, str)
}

func PayloadFromHexString(str string) (*Cryptor, error) {
	l := &Cryptor{}
	return l, fromHexString(l, str)
}
