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
	V := MultiplyX(generator, g, v)
	h := Hash(*g, V, X, userID)
	r := new(big.Int).Sub(v, new(big.Int).Mul(x, h))
	r = ModuloN(r, n)
	return &SchnorrZKP{V, r}
}

func VerifyZKP(
	curve elliptic.Curve,
	generator []byte,
	X []byte,
	zkp SchnorrZKP,
	userID string,
) bool {
	h := Hash(generator, zkp.V, X, userID)

	if X == nil {
		return false
	}

	Xx, Xy := elliptic.UnmarshalCompressed(curve, X)
	if Xx == nil || Xy == nil {
		return false
	}

	if !curve.IsOnCurve(Xx, Xy) {
		return false
	}

	Vx, Vy := elliptic.UnmarshalCompressed(curve, zkp.V)
	if Vx == nil || Vy == nil {
		return false
	}

	rGx, rGy := curve.ScalarBaseMult(zkp.R.Bytes())
	hXx, hXy := curve.ScalarMult(Xx, Xy, h.Bytes())
	sumX, sumY := curve.Add(rGx, rGy, hXx, hXy)

	return sumX.Cmp(Vx) == 0 && sumY.Cmp(Vy) == 0
}
