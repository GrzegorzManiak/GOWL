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
	r := Multiply(x, h)
	r = new(big.Int).Sub(v, r)
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

	if X == nil || zkp.V == nil || zkp.R == nil {
		return false
	}

	xX, xY := elliptic.UnmarshalCompressed(curve, X)
	if IsInfinity(xX, xY) {
		return false
	}

	if xX.Cmp(big.NewInt(0)) == -1 || xX.Cmp(new(big.Int).Sub(curve.Params().N, big.NewInt(1))) == 1 {
		return false
	}

	if xY.Cmp(big.NewInt(0)) == -1 || xY.Cmp(new(big.Int).Sub(curve.Params().N, big.NewInt(1))) == 1 {
		return false
	}

	if !curve.IsOnCurve(xX, xY) {
		return false
	}

	xXh := MultiplyX(curve, &X, calculateCofactor(curve))
	xXhX, xXhY := elliptic.UnmarshalCompressed(curve, xXh)
	if IsInfinity(xXhX, xXhY) {
		return false
	}

	gRxhmn := Add(curve, MultiplyX(curve, &generator, zkp.R), MultiplyX(curve, &X, ModuloN(h, curve.Params().N)))
	return Equal(curve, zkp.V, gRxhmn)
}
