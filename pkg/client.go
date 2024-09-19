package pkg

import (
	"crypto/elliptic"
	"math/big"
)

type Client struct {
	UserIdentifier string
	UserPassword   string
	ServerName     string
	Curve          elliptic.Curve
	CurveParams    *elliptic.CurveParams

	// -- Registration -- //
	t *big.Int // T = t * G
	π *big.Int // PI = H(t) mod N
	T []byte   // T_ = t * G

	// -- Authentication Init -- //
	x1 *big.Int    // x1 ∈R [0, q − 1], X1 = gx1
	X1 []byte      // X1 = x1 * G
	Π1 *SchnorrZKP // Π1 = ZKP{x1}
	x2 *big.Int    // x2 ∈R [1, q − 1], X2 = gx2
	X2 []byte      // X2 = x2 * G
	Π2 *SchnorrZKP // Π2 = ZKP{x2}
	G  *[]byte     // G = g
}

func ClientInit(user string, pass string, serverName string, curve elliptic.Curve) *Client {
	curveParams := curve.Params()
	t := ModuloN(Hash(user, pass), curveParams.N)
	π := ModuloN(Hash(t), curveParams.N)
	T := MultiplyG(curve, t)
	G := elliptic.MarshalCompressed(curve, curveParams.Gx, curveParams.Gy)

	return &Client{
		UserIdentifier: user,
		UserPassword:   pass,
		ServerName:     serverName,
		Curve:          curve,
		t:              t,
		π:              π,
		T:              T,
		CurveParams:    curveParams,
		G:              &G,
	}
}

func (c *Client) Register() (t *big.Int, pi *big.Int, T []byte) {
	return c.t, c.π, c.T
}

func (c *Client) AuthInit() (x1 *big.Int, Π1 *SchnorrZKP, x2 *big.Int, Π2 *SchnorrZKP) {
	c.x1 = GenerateKey(c.CurveParams.N)
	c.X1 = MultiplyG(c.Curve, c.x1)
	c.Π1 = GenerateZKPGProvided(c.Curve, c.G, c.CurveParams.N, c.x1, c.X1, c.UserIdentifier)

	c.x2 = GenerateKey(c.CurveParams.N)
	c.X2 = MultiplyG(c.Curve, c.x2)
	c.Π2 = GenerateZKPGProvided(c.Curve, c.G, c.CurveParams.N, c.x2, c.X2, c.UserIdentifier)

	return c.x1, c.Π1, c.x2, c.Π2
}
