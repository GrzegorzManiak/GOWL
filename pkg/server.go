package pkg

import (
	"crypto/elliptic"
	"math/big"
)

type Server struct {
	ServerName  string
	Curve       elliptic.Curve
	CurveParams *elliptic.CurveParams

	// -- Registration -- //
	x3 *big.Int    // x3 ∈R [0, q − 1]
	X3 []byte      // X3 = x3 * G
	Π3 *SchnorrZKP // Π4 = ZKP{x3}

	// -- Authentication Init -- //
	x4 *big.Int    // x4 ∈R [0, q − 1]
	X4 []byte      // X4 = x4 * G
	Π4 *SchnorrZKP // Π4 = ZKP{x4}
	β  []byte      // β = (X1X2X3)x4·π
	Πβ *SchnorrZKP // Πβ = ZKP{x4 · π}
}

func ServerInit(name string, curve elliptic.Curve) *Server {
	return &Server{
		ServerName:  name,
		Curve:       curve,
		CurveParams: curve.Params(),
	}
}

func (s *Server) RegisterUser() ([]byte, *SchnorrZKP) {
	s.x3 = GenerateKey(s.CurveParams.N)
	s.X3 = MultiplyG(s.Curve, s.x3)
	s.Π3 = GenerateZKP(s.Curve, s.CurveParams.N, s.x3, s.X3, s.ServerName)
	return s.X3, s.Π3
}

func (s *Server) AuthInit(
	user string,
	π *big.Int,
	X1 []byte,
	X2 []byte,
	Π1 *SchnorrZKP,
	Π2 *SchnorrZKP,
) ([]byte, []byte, []byte, *SchnorrZKP, *SchnorrZKP, *SchnorrZKP) {
	s.x4 = GenerateKey(s.CurveParams.N)
	s.X4 = MultiplyG(s.Curve, s.x4)
	s.Π4 = GenerateZKP(s.Curve, s.CurveParams.N, s.x4, s.X4, s.ServerName)

	Gβ := Add(s.Curve, X1, X2)
	Gβ = Add(s.Curve, Gβ, s.X3)

	x4Pi := new(big.Int).Mul(s.x4, π)
	x4Pi.Mod(x4Pi, s.CurveParams.N)
	s.β = MultiplyX(s.Curve, &Gβ, x4Pi)
	s.Πβ = GenerateZKPGProvided(s.Curve, &s.β, s.CurveParams.N, x4Pi, s.β, user)

	return s.X3, s.X4, s.β, s.Π3, s.Π4, s.Πβ
}

//
//Gβ := Add(s.Curve, X1, s.X3)
//Gβ = Add(s.Curve, Gβ, s.X4)
//
//x2π := new(big.Int).SetBytes(X2)
//x2π = new(big.Int).Mul(x2π, s.CurveParams.N)
//β = MultiplyX(s.Curve, &Gβ, x2π)
//
//println("Gβ: ", new(big.Int).SetBytes(Gβ).String())
//println("β: ", new(big.Int).SetBytes(β).String())
//
//zkpX2s := GenerateZKP(s.Curve, s.CurveParams.N, x2π, β, user)
//rawClientKey := ComputeRawClientKey(s.Curve, β, s.X4, x2π, π, s.CurveParams.N)
//
//println("Raw Client Key: ", new(big.Int).SetBytes(rawClientKey).String())
//println("zkpX2s.V: ", new(big.Int).SetBytes(zkpX2s.V).String())
//println("zkpX2s.R: ", new(big.Int).SetBytes(zkpX2s.R.Bytes()).String())
//
//return nil, nil, nil, nil, nil, nil, nil
