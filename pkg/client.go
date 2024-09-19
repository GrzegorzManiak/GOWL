package pkg

import (
	"crypto/elliptic"
	"math/big"
)

//type Client struct {
//	UserIdentifier string
//	UserPassword   string
//	ServerName     string
//	Curve          elliptic.Curve
//
//	t  *big.Int // t = H(ID, P)
//	pi *big.Int // pi = H(t) mod N
//	t_ []byte   // t_ = t * G
//}
//
//func (c *Client) Register() (t *big.Int, pi *big.Int, T []byte) {
//	curveParams := c.Curve.Params()
//	c.t = ModuloN(Hash(c.UserIdentifier, c.UserPassword), curveParams.N)
//	c.pi = ModuloN(Hash(c.t), curveParams.N)
//	c.t_ = MultiplyG(c.Curve, c.t)
//	return c.t, c.pi, c.t_
//}

type Client struct {
	UserIdentifier string
	UserPassword   string
	ServerName     string
	Curve          elliptic.Curve
	CurveParams    *elliptic.CurveParams

	t *big.Int // T = t * G
	π *big.Int // PI = H(t) mod N
	T []byte   // T_ = t * G
}

func ClientInit(user string, pass string, serverName string, curve elliptic.Curve) *Client {
	curveParams := curve.Params()
	t := ModuloN(Hash(user, pass), curveParams.N)
	π := ModuloN(Hash(t), curveParams.N)
	T := MultiplyG(curve, t)

	return &Client{
		UserIdentifier: user,
		UserPassword:   pass,
		ServerName:     serverName,
		Curve:          curve,
		t:              t,
		π:              π,
		T:              T,
		CurveParams:    curveParams,
	}
}

func (c *Client) Register() (t *big.Int, pi *big.Int, T []byte) {
	return c.t, c.π, c.T
}
