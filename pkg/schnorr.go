package pkg

import (
	"crypto/elliptic"
	"math/big"
)

type SchnorrZKP struct {
	V []byte
	R *big.Int
}

func GenerateZKP(generator elliptic.Curve, n *big.Int, x *big.Int, X []byte, userID string) SchnorrZKP {
	v := Generatex3(n)
	V := MultiplyG(generator, v)
	curveParams := generator.Params()
	// TODO: Move g out of this function as to not generate it every time
	g := elliptic.MarshalCompressed(generator, curveParams.Gx, curveParams.Gy)
	h := Hash(g, V, X, userID)
	r := new(big.Int).Sub(v, new(big.Int).Mul(x, h))
	r = ModuloN(r, n)
	return SchnorrZKP{V, r}
}
