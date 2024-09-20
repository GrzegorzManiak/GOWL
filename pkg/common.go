package pkg

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

const (
	SessionKey      = "session_key"
	ConfirmationKey = "confirmation_key"
)

func ModuloN(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Mod(x, n)
}

func Multiply(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mul(x, y)
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

func GenerateKey(n *big.Int) *big.Int {
	return HighEntropyRandom(big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)))
}

func GetG(curve elliptic.Curve) *[]byte {
	curveParams := curve.Params()
	g := elliptic.MarshalCompressed(curve, curveParams.Gx, curveParams.Gy)
	return &g
}

func MultiplyG(curve elliptic.Curve, x *big.Int) []byte {
	curveParams := curve.Params()
	tx, ty := curve.ScalarMult(curveParams.Gx, curveParams.Gy, x.Bytes())
	return elliptic.MarshalCompressed(curve, tx, ty)
}

func MultiplyX(curve elliptic.Curve, X *[]byte, x *big.Int) []byte {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, *X)
	tx, ty := curve.ScalarMult(x1x, x1y, x.Bytes())
	return elliptic.MarshalCompressed(curve, tx, ty)
}

func Add(curve elliptic.Curve, x1 []byte, x2 []byte) []byte {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, x1)
	x2x, x2y := elliptic.UnmarshalCompressed(curve, x2)
	tx, ty := curve.Add(x1x, x1y, x2x, x2y)
	return elliptic.MarshalCompressed(curve, tx, ty)
}

// Subtract > All credit goes to ChatGPT, I had no clue how to implement this
// myself.
func Subtract(curve elliptic.Curve, x1 []byte, x2 []byte) []byte {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, x1)
	x2x, x2y := elliptic.UnmarshalCompressed(curve, x2)
	negY2 := new(big.Int).Neg(x2y)
	if negY2.Sign() < 0 {
		negY2.Add(negY2, curve.Params().P)
	}
	tx, ty := curve.Add(x1x, x1y, x2x, negY2)
	return elliptic.MarshalCompressed(curve, tx, ty)
}

func Equal(curve elliptic.Curve, x1 []byte, x2 []byte) bool {
	x1x, x1y := elliptic.UnmarshalCompressed(curve, x1)
	x2x, x2y := elliptic.UnmarshalCompressed(curve, x2)
	return x1x.Cmp(x2x) == 0 && x1y.Cmp(x2y) == 0
}

func IsInfinity(xX *big.Int, xY *big.Int) bool {
	return xX == nil && xY == nil
}

func calculateCofactor(curve elliptic.Curve) *big.Int {
	order := curve.Params().N
	totalPoints := new(big.Int).Set(order)
	cofactor := new(big.Int).Div(totalPoints, order)
	return cofactor
}
