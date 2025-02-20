package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
