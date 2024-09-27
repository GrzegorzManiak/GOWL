package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

func GenerateKey(curve elliptic.Curve) *big.Int {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(key.D.Bytes())
}

func ModuloN(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(x, n), n)
}

func Multiply(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mul(x, y)
}

func Subtract(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Sub(x, y)
}

func B64Encode(data interface{}) string {
	switch data.(type) {
	case *big.Int:
		return base64.StdEncoding.EncodeToString(data.(*big.Int).Bytes())

	case []byte:
		return B64Encode(new(big.Int).SetBytes(data.([]byte)))

	default:
		panic("Invalid type passed to Encode")
	}
}

func B64DecodeBytes(encoded string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return decoded
}

func B64DecodeBigInt(encoded string) *big.Int {
	return new(big.Int).SetBytes(B64DecodeBytes(encoded))
}
