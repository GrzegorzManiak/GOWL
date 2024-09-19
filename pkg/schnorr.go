package pkg

import (
	"crypto/elliptic"
	"math/big"
)

type SchnorrZKP struct {
	V []byte
	R *big.Int
}

func GenerateZKP(
	generator elliptic.Curve,
	n *big.Int,
	x *big.Int,
	X []byte,
	userID string,
) *SchnorrZKP {
	curveParams := generator.Params()
	g := elliptic.MarshalCompressed(generator, curveParams.Gx, curveParams.Gy)
	return GenerateZKPGProvided(generator, &g, n, x, X, userID)
}

func GenerateZKPGProvided(
	generator elliptic.Curve,
	g *[]byte,
	n *big.Int,
	x *big.Int,
	X []byte,
	userID string,
) *SchnorrZKP {
	v := GenerateKey(n)
	V := MultiplyG(generator, v)
	h := Hash(*g, V, X, userID)
	r := new(big.Int).Sub(v, new(big.Int).Mul(x, h))
	r = ModuloN(r, n)
	return &SchnorrZKP{V, r}
}
