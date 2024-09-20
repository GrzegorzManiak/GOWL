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
	x1 *big.Int    // x1 ∈R [0, q − 1]
	X1 []byte      // X1 = x1 * G
	Π1 *SchnorrZKP // Π1 = ZKP{x1}
	x2 *big.Int    // x2 ∈R [1, q − 1]
	X2 []byte      // X2 = x2 * G
	Π2 *SchnorrZKP // Π2 = ZKP{x2}
	G  *[]byte     // G = g

	// -- Authentication Validate -- //
	α  *[]byte     // α = (X1X3X4)x2·π
	Πα *SchnorrZKP // Πα = ZKP{x2 · π}
	r  *big.Int    // r = x1 − t · h mod q
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

func (c *Client) AuthInit() (x1 []byte, Π1 *SchnorrZKP, x2 []byte, Π2 *SchnorrZKP) {
	c.x1 = GenerateKey(c.CurveParams.N)
	c.X1 = MultiplyG(c.Curve, c.x1)
	c.Π1 = GenerateZKPGProvided(c.Curve, c.G, c.CurveParams.N, c.x1, c.X1, c.UserIdentifier)

	c.x2 = GenerateKey(c.CurveParams.N)
	c.X2 = MultiplyG(c.Curve, c.x2)
	c.Π2 = GenerateZKPGProvided(c.Curve, c.G, c.CurveParams.N, c.x2, c.X2, c.UserIdentifier)

	return c.X1, c.Π1, c.X2, c.Π2
}

func (c *Client) AuthValidate(
	X3 []byte,
	X4 []byte,
	β []byte,
	Π3 *SchnorrZKP,
	Π4 *SchnorrZKP,
	Πβ *SchnorrZKP,
) {
	c.x2, _ = new(big.Int).SetString("28048054698464670087075807131323991123069734699031281255718814425862565568869", 10)
	X1RAW, _ := new(big.Int).SetString("291527873065038658029434543999156023191731888933086013964755314683727060351946", 10)
	c.X1 = X1RAW.Bytes()

	Gα := Add(c.Curve, c.X1, X3)
	Gα = Add(c.Curve, Gα, X4)

	x2π := new(big.Int).Mul(c.x2, c.π)
	x2π.Mod(x2π, c.CurveParams.N)
	α := MultiplyX(c.Curve, &Gα, x2π)
	c.α = &α
	c.Πα = GenerateZKPGProvided(c.Curve, &Gα, c.CurveParams.N, x2π, α, c.UserIdentifier)

	X4x2π := MultiplyX(c.Curve, &X4, x2π)
	rawClientKey := Subtract(c.Curve, β, X4x2π)
	rawClientKey = MultiplyX(c.Curve, &rawClientKey, c.x2)

	clientSessionKey := Hash(rawClientKey, SessionKey)
	clientKCKey := Hash(rawClientKey, ConfirmationKey)

	hTranscript := Hash(
		rawClientKey,
		c.UserIdentifier,
		c.X1, c.X2,
		c.Π1, c.Π2,
		c.ServerName,
		X3, X4,
		Π3, Π4,
		β, Πβ,
		α, c.Πα,
	)

	hTranscript = ModuloN(hTranscript, c.CurveParams.N)

	tLogin := ModuloN(Hash(c.UserIdentifier, c.UserPassword), c.CurveParams.N)
	rValue := new(big.Int).Sub(c.x1, new(big.Int).Mul(tLogin, hTranscript))
	rValue.Mod(rValue, c.CurveParams.N)
	c.r = rValue

	clientKCTag := DeriveHMACTag(
		clientKCKey,
		"KC_1_U",
		c.UserIdentifier,
		c.ServerName,
		c.X1, c.X2,
		X3, X4,
	)

	println("Client Key Confirmation Tag: ", clientKCTag.String())
	println("Client Session Key: ", clientSessionKey.String())

}
