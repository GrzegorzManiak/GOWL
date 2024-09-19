package pkg

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
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

func Generatex3(n *big.Int) *big.Int {
	return HighEntropyRandom(big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)))
}

func MultiplyG(curve elliptic.Curve, x *big.Int) []byte {
	curveParams := curve.Params()
	tx, ty := curve.ScalarMult(curveParams.Gx, curveParams.Gy, x.Bytes())
	return elliptic.MarshalCompressed(curve, tx, ty)
}
