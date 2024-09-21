package crypto

import (
	"crypto/rand"
	"math/big"
)

func HighEntropyRandom(min *big.Int, max *big.Int) *big.Int {
	rangeBigInt := new(big.Int).Sub(max, min)
	randomBigInt, err := rand.Int(rand.Reader, rangeBigInt)
	if err != nil {
		panic(err)
	}
	randomBigInt.Add(randomBigInt, min)
	return randomBigInt
}

func GenerateKey(n *big.Int) *big.Int {
	return HighEntropyRandom(big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)))
}

func ModuloN(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Mod(x, n)
}

func Multiply(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mul(x, y)
}

func Subtract(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Sub(x, y)
}
