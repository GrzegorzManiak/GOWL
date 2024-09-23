package crypto

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
	g := GetG(generator)
	return GenerateZKPGProvided(generator, g, n, x, X, userID) // No need for &g
}

func GenerateZKPGProvided(
	generator elliptic.Curve,
	g []byte, // No pointer needed
	n *big.Int,
	x *big.Int,
	X []byte,
	prover string,
) *SchnorrZKP {
	v := GenerateKey(n)
	V := MultiplyPoint(generator, &g, v)
	h := Hash(g, V, X, prover)
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
	prover string,
) bool {
	h := Hash(generator, zkp.V, X, prover)

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

	xXh := MultiplyPoint(curve, &X, CalculateCofactor(curve))
	xXhX, xXhY := elliptic.UnmarshalCompressed(curve, xXh)
	if IsInfinity(xXhX, xXhY) {
		return false
	}

	gRxhmn := AddPoints(curve, MultiplyPoint(curve, &generator, zkp.R), MultiplyPoint(curve, &X, ModuloN(h, curve.Params().N)))
	return PointsEqual(curve, zkp.V, gRxhmn)
}
