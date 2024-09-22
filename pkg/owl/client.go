package owl

import (
	"crypto/elliptic"
	"errors"
	"github.com/GrzegorzManiak/GOWL/pkg/crypto"
	"math/big"
)

type Client struct {
	UserIdentifier string
	UserPassword   string
	ServerName     string
	Curve          elliptic.Curve
	CurveParams    *elliptic.CurveParams

	t *big.Int
	π *big.Int
	T []byte
}

func ClientInit(
	user string,
	pass string,
	serverName string,
	curve elliptic.Curve,
) (*Client, error) {

	if user == serverName {
		return nil, errors.New("user and server name cannot be the same")
	}

	curveParams := curve.Params()
	t := crypto.ModuloN(crypto.Hash(user, pass), curveParams.N)
	π := crypto.ModuloN(crypto.Hash(t), curveParams.N)
	T := crypto.MultiplyG(curve, t)

	return &Client{
		UserIdentifier: user,
		UserPassword:   pass,
		ServerName:     serverName,
		Curve:          curve,
		t:              t,
		π:              π,
		T:              T,
		CurveParams:    curveParams,
	}, nil
}

func (client *Client) Register() *RegistrationRequest {
	payload := &RegistrationRequestPayload{
		U: client.UserIdentifier,
		π: client.π,
		T: client.T,
	}

	return &RegistrationRequest{
		Payload: payload,
		t:       client.t,
	}
}

func (client *Client) AuthInit() *ClientAuthInitRequest {
	G := crypto.GetG(client.Curve)
	x1 := crypto.GenerateKey(client.CurveParams.N)
	X1 := crypto.MultiplyG(client.Curve, x1)
	Π1 := crypto.GenerateZKPGProvided(client.Curve, G, client.CurveParams.N, x1, X1, client.UserIdentifier)

	x2 := crypto.GenerateKey(client.CurveParams.N)
	X2 := crypto.MultiplyG(client.Curve, x2)
	Π2 := crypto.GenerateZKPGProvided(client.Curve, G, client.CurveParams.N, x2, X2, client.UserIdentifier)

	payload := &ClientAuthInitRequestPayload{
		U:  client.UserIdentifier,
		X1: X1,
		X2: X2,
		Π1: Π1,
		Π2: Π2,
	}

	return &ClientAuthInitRequest{
		Payload: payload,
		x1:      x1,
		x2:      x2,
	}
}

func (client *Client) AuthValidate(
	clientInit *ClientAuthInitRequest,
	serverInit *ServerAuthInitResponsePayload,
) (*ClientAuthValidateRequest, error) {

	curve := client.Curve
	G := crypto.GetG(client.Curve)

	if !crypto.VerifyZKP(curve, G, serverInit.X3, *serverInit.Π3, client.ServerName) {
		return nil, errors.New("ZKP Verification Failed for Π3")
	}

	if !crypto.VerifyZKP(curve, G, serverInit.X4, *serverInit.Π4, client.ServerName) {
		return nil, errors.New("ZKP Verification Failed for Π4")
	}

	Gβ := crypto.AddPoints(curve, crypto.AddPoints(curve, clientInit.Payload.X1, clientInit.Payload.X2), serverInit.X3)
	if !crypto.VerifyZKP(curve, Gβ, serverInit.B, *serverInit.Πβ, client.ServerName) {
		return nil, errors.New("ZKP Verification Failed for Πβ")
	}

	Gα := crypto.AddPoints(curve, crypto.AddPoints(curve, clientInit.Payload.X1, serverInit.X3), serverInit.X4)
	x2π := crypto.ModuloN(crypto.Multiply(clientInit.x2, client.π), client.CurveParams.N)
	α := crypto.MultiplyPoint(curve, &Gα, x2π)
	Πα := crypto.GenerateZKPGProvided(curve, Gα, client.CurveParams.N, x2π, α, client.UserIdentifier)

	rawClientKey := crypto.SubtractPoints(curve, serverInit.B, crypto.MultiplyPoint(curve, &serverInit.X4, x2π))
	rawClientKey = crypto.MultiplyPoint(curve, &rawClientKey, clientInit.x2)

	clientSessionKey := crypto.Hash(rawClientKey, SessionKey)
	clientKCKey := crypto.Hash(rawClientKey, ConfirmationKey)

	hTranscript := crypto.Hash(
		rawClientKey,
		client.UserIdentifier,
		clientInit.Payload.X1, clientInit.Payload.X2,
		clientInit.Payload.Π1, clientInit.Payload.Π2,
		client.ServerName,
		serverInit.X3, serverInit.X4,
		*serverInit.Π3, *serverInit.Π4,
		serverInit.B, *serverInit.Πβ,
		α, Πα,
	)

	hTranscript = crypto.ModuloN(hTranscript, client.CurveParams.N)
	rValue := crypto.Subtract(clientInit.x1, crypto.Multiply(client.t, hTranscript))
	rValue = crypto.ModuloN(rValue, client.CurveParams.N)

	clientKCTag := crypto.DeriveHMACTag(
		clientKCKey,
		ClientKCKeyTag,
		client.UserIdentifier,
		client.ServerName,
		clientInit.Payload.X1, clientInit.Payload.X2,
		serverInit.X3, serverInit.X4,
	)

	payload := &ClientAuthValidateRequestPayload{
		ClientKCTag: clientKCTag,
		α:           α,
		Πα:          Πα,
		r:           rValue,
	}

	return &ClientAuthValidateRequest{
		Payload:          payload,
		RawClientKey:     rawClientKey,
		ClientSessionKey: clientSessionKey,
		ClientKCKey:      clientKCKey,
		HTranscript:      hTranscript,
	}, nil
}

func (client *Client) VerifyResponse(
	clientInit *ClientAuthInitRequest,
	clientValidate *ClientAuthValidateRequest,
	serverInit *ServerAuthInitResponsePayload,
	serverValidate *ServerAuthValidateResponsePayload,
) error {

	serverKCTag2 := crypto.DeriveHMACTag(
		clientValidate.ClientKCKey,
		ServerKCKeyTag,
		client.ServerName,
		client.UserIdentifier,
		serverInit.X3, serverInit.X4,
		clientInit.Payload.X1, clientInit.Payload.X2,
	)

	if serverKCTag2.Cmp(serverValidate.ServerKCTag) != 0 {
		return errors.New("ERROR: invalid r (client authentication failed)")
	}

	return nil
}
