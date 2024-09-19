package pkg

import (
	"crypto/ecdh"
	"crypto/rand"
	"math/big"
)

// -- Curves that the user can use
var (
	P256 = ecdh.P256
	P384 = ecdh.P384
	P521 = ecdh.P521
)

func ModuloN(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Mod(x, n)
}

func ByteToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func HighEntropyRandom(min *big.Int, max *big.Int) *big.Int {
	rangeBigInt := new(big.Int).Sub(max, min)
	randomBigInt, err := rand.Int(rand.Reader, rangeBigInt)
	if err != nil {
		panic(err)
	}
	randomBigInt.Add(randomBigInt, min)
	return randomBigInt
}
