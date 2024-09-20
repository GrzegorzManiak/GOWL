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
	Π1 *SchnorrZKP, // TODO: Implement ZKP Verification
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

func (s *Server) AuthValidate(
	π *big.Int,
	T []byte,
	user string,
	X1 []byte,
	X2 []byte,
	Π1 *SchnorrZKP, // TODO: Implement ZKP Verification
	Π2 *SchnorrZKP,
	α *[]byte,
	Πα *SchnorrZKP,
	r *big.Int) {

	x4π := new(big.Int).Mul(s.x4, π)                                // x4.multiply(pi)
	X2x4π := MultiplyX(s.Curve, &X2, x4π.Mod(x4π, s.CurveParams.N)) // X2.multiply(x4π)
	rawServerKey := Subtract(s.Curve, *α, X2x4π)                    // X2x4π.subtract(α)
	rawServerKey = MultiplyX(s.Curve, &rawServerKey, s.x4)          // rawServerKey.multiply(x4)

	serverSessionKey := Hash(rawServerKey, SessionKey)
	serverKCKey := Hash(rawServerKey, ConfirmationKey)

	hServer := Hash(
		rawServerKey,
		user,
		X1, X2,
		Π1, Π2,
		s.ServerName,
		s.X3, s.X4,
		s.Π3, s.Π4,
		s.β, s.Πβ,
		*α, Πα,
	)

	hServer = ModuloN(hServer, s.CurveParams.N)

	clientKCTag2 := DeriveHMACTag(
		serverKCKey,
		"KC_1_U",
		user,
		s.ServerName,
		X1, X2,
		s.X3, s.X4,
	)

	serverKCTag := DeriveHMACTag(
		serverKCKey,
		"KC_1_V",
		s.ServerName,
		user,
		s.X3, s.X4,
		X1, X2,
	)

	println("RawServerKey:", new(big.Int).SetBytes(rawServerKey).String())
	println("serverSessionKey:", serverSessionKey.String())
	println("serverKCKey:", serverKCKey.String())
	println("Server hTranscript:", hServer.String())
	println("Server KCTag:", serverKCTag.String())
	println("Client KCTag:", clientKCTag2.String())
}
