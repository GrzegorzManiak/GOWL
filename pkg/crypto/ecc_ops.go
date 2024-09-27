package crypto

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

func GetG(curve elliptic.Curve) []byte {
	curveParams := curve.Params()
	return elliptic.MarshalCompressed(curve, curveParams.Gx, curveParams.Gy)
}

func MultiplyG(curve elliptic.Curve, x *big.Int) []byte {
	curveParams := curve.Params()
	tx, ty := curve.ScalarMult(curveParams.Gx, curveParams.Gy, x.Bytes())
	return elliptic.MarshalCompressed(curve, tx, ty)
}

func MultiplyPoint(curve elliptic.Curve, X *[]byte, x *big.Int) ([]byte, error) {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, *X)
	if x1x == nil || x1y == nil {
		return nil, errors.New("Point is invalid")
	}
	tx, ty := curve.ScalarMult(x1x, x1y, x.Bytes())
	return elliptic.MarshalCompressed(curve, tx, ty), nil
}

func AddPoints(curve elliptic.Curve, x1 []byte, x2 []byte) ([]byte, error) {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, x1)
	x2x, x2y := elliptic.UnmarshalCompressed(curve, x2)
	if x1x == nil || x1y == nil || x2x == nil || x2y == nil {
		return nil, errors.New("one or more points are invalid")
	}
	tx, ty := curve.Add(x1x, x1y, x2x, x2y)
	return elliptic.MarshalCompressed(curve, tx, ty), nil
}

func SubtractPoints(curve elliptic.Curve, x1 []byte, x2 []byte) ([]byte, error) {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, x1)
	x2x, x2y := elliptic.UnmarshalCompressed(curve, x2)
	if x1x == nil || x1y == nil || x2x == nil || x2y == nil {
		return nil, errors.New("one or more points are invalid")
	}
	negY2 := new(big.Int).Neg(x2y)
	if negY2.Sign() < 0 {
		negY2.Add(negY2, curve.Params().P)
	}
	tx, ty := curve.Add(x1x, x1y, x2x, negY2)
	return elliptic.MarshalCompressed(curve, tx, ty), nil
}

func PointsEqual(curve elliptic.Curve, x1 []byte, x2 []byte) bool {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, x1)
	x2x, x2y := elliptic.UnmarshalCompressed(curve, x2)
	if x1x == nil || x1y == nil || x2x == nil || x2y == nil {
		return false
	}
	return x1x.Cmp(x2x) == 0 && x1y.Cmp(x2y) == 0
}

func IsInfinity(xX *big.Int, xY *big.Int) bool {
	return xX == nil && xY == nil
}

func CalculateCofactor(curve elliptic.Curve) *big.Int {
	order := curve.Params().N
	totalPoints := new(big.Int).Set(order)
	cofactor := new(big.Int).Div(totalPoints, order)
	return cofactor
}
