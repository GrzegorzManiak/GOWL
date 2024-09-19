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
	return GenerateZKPGProvided(generator, GetG(generator), n, x, X, userID)
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

func GetG(curve elliptic.Curve) *[]byte {
	curveParams := curve.Params()
	g := elliptic.MarshalCompressed(curve, curveParams.Gx, curveParams.Gy)
	return &g
}

func (zkp SchnorrZKP) VerifyZKP(
	generator elliptic.Curve,
	X []byte,
	userID string,
) bool {
	//G := GetG(generator)
	//h := Hash(*G, zkp.V, X, userID)
	//x, y := elliptic.Unmarshal(generator, X)
	//vx, vy := elliptic.Unmarshal(generator, zkp.V)
	return false
}
