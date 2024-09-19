package pkg

import (
	"crypto/elliptic"
	"math/big"
)

type Server struct {
	ServerName  string
	Curve       elliptic.Curve
	CurveParams *elliptic.CurveParams

	x3 *big.Int
	X3 []byte
	Π4 SchnorrZKP
}

func ServerInit(name string, curve elliptic.Curve) *Server {
	return &Server{
		ServerName:  name,
		Curve:       curve,
		CurveParams: curve.Params(),
	}
}

// user string, PI *big.Int, T []byte
func (s *Server) RegisterUser() ([]byte, SchnorrZKP) {
	s.x3 = Generatex3(s.CurveParams.N)
	s.X3 = MultiplyG(s.Curve, s.x3)
	s.Π4 = GenerateZKP(s.Curve, s.CurveParams.N, s.x3, s.X3, s.ServerName)
	return s.X3, s.Π4
}
