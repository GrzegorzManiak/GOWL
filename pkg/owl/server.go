package owl

import (
	"crypto/elliptic"
	"errors"
	"github.com/GrzegorzManiak/GOWL/pkg/crypto"
)

type Server struct {
	UserIdentifier   string
	ServerName       string
	Curve            elliptic.Curve
	CurveParams      *elliptic.CurveParams
	UserRegistration *RegistrationRequestPayload
}

func ServerInit(
	server string,
	curve elliptic.Curve,
	userRegistration *RegistrationRequestPayload,
) (*Server, error) {
	user := userRegistration.U

	if user == server {
		return nil, errors.New("user and server name cannot be the same")
	}

	return &Server{
		UserIdentifier:   user,
		ServerName:       server,
		Curve:            curve,
		CurveParams:      curve.Params(),
		UserRegistration: userRegistration,
	}, nil
}

func (server *Server) RegisterUser() *RegistrationResponse {
	x3 := crypto.GenerateKey(server.CurveParams.N)
	X3 := crypto.MultiplyG(server.Curve, x3)
	Π3 := crypto.GenerateZKP(server.Curve, server.CurveParams.N, x3, X3, server.ServerName)

	payload := &RegistrationResponsePayload{
		X3: X3,
		Π3: Π3,
	}

	return &RegistrationResponse{
		Payload: payload,
	}
}

func (server *Server) AuthInit(
	serverRegistration *RegistrationResponse,
	clientInit *ClientAuthInitRequestPayload,
) (*ServerAuthInitResponse, error) {
	G := crypto.GetG(server.Curve)
	curve := server.Curve

	if crypto.VerifyZKP(server.Curve, G, clientInit.X1, *clientInit.Π1, server.UserIdentifier) == false {
		return nil, errors.New("ZKP Verification Failed for Π1")
	}

	if crypto.VerifyZKP(server.Curve, G, clientInit.X2, *clientInit.Π2, server.UserIdentifier) == false {
		return nil, errors.New("ZKP Verification Failed for Π2")
	}

	if server.UserIdentifier == server.ServerName {
		return nil, errors.New("user and Server cannot have the same name")
	}

	x4 := crypto.GenerateKey(server.CurveParams.N)
	X4 := crypto.MultiplyG(curve, x4)
	Π4 := crypto.GenerateZKP(curve, server.CurveParams.N, x4, X4, server.ServerName)
	Gβ := crypto.AddPoints(curve, crypto.AddPoints(curve, clientInit.X1, clientInit.X2), serverRegistration.Payload.X3)
	x4Pi := crypto.ModuloN(crypto.Multiply(x4, server.UserRegistration.π), server.CurveParams.N)
	β := crypto.MultiplyPoint(curve, &Gβ, x4Pi)
	Πβ := crypto.GenerateZKPGProvided(curve, Gβ, server.CurveParams.N, x4Pi, β, server.ServerName)

	payload := &ServerAuthInitResponsePayload{
		X3: serverRegistration.Payload.X3,
		X4: X4,
		Π3: serverRegistration.Payload.Π3,
		Π4: Π4,
		β:  β,
		Πβ: Πβ,
	}

	return &ServerAuthInitResponse{
		Payload: payload,
		x4:      x4,
		Gβ:      Gβ,
	}, nil
}

func (server *Server) AuthValidate(
	clientInit *ClientAuthInitRequestPayload,
	clientValidate *ClientAuthValidateRequestPayload,
	serverInit *ServerAuthInitResponse,
) (*ServerAuthValidateResponse, error) {
	curve := server.Curve
	Gα := crypto.AddPoints(curve, clientInit.X1, serverInit.Payload.X3)
	Gα = crypto.AddPoints(curve, Gα, serverInit.Payload.X4)

	if crypto.VerifyZKP(curve, Gα, clientValidate.α, *clientValidate.Πα, server.UserIdentifier) == false {
		return nil, errors.New("ZKP Verification Failed for Πα")
	}

	x4π := crypto.Multiply(serverInit.x4, server.UserRegistration.π)
	X2x4π := crypto.MultiplyPoint(curve, &clientInit.X2, crypto.ModuloN(x4π, server.CurveParams.N))

	rawServerKey := crypto.SubtractPoints(server.Curve, clientValidate.α, X2x4π)
	rawServerKey = crypto.MultiplyPoint(server.Curve, &rawServerKey, serverInit.x4)
	serverSessionKey := crypto.Hash(rawServerKey, SessionKey)
	serverKCKey := crypto.Hash(rawServerKey, ConfirmationKey)

	hServer := crypto.Hash(
		rawServerKey,
		server.UserIdentifier,
		clientInit.X1, clientInit.X2,
		clientInit.Π1, clientInit.Π2,
		server.ServerName,
		serverInit.Payload.X3, serverInit.Payload.X4,
		serverInit.Payload.Π3, serverInit.Payload.Π4,
		serverInit.Payload.β, serverInit.Payload.Πβ,
		clientValidate.α, clientValidate.Πα,
	)

	hServer = crypto.ModuloN(hServer, server.CurveParams.N)

	clientKCTag2 := crypto.DeriveHMACTag(
		serverKCKey,
		ClientKCKeyTag,
		server.UserIdentifier,
		server.ServerName,
		clientInit.X1, clientInit.X2,
		serverInit.Payload.X3, serverInit.Payload.X4,
	)

	if clientValidate.ClientKCTag.Cmp(clientKCTag2) != 0 {
		return nil, errors.New("client authentication failed, ClientKCTag mismatch")
	}

	serverKCTag := crypto.DeriveHMACTag(
		serverKCKey,
		ServerKCKeyTag,
		server.ServerName,
		server.UserIdentifier,
		serverInit.Payload.X3, serverInit.Payload.X4,
		clientInit.X1, clientInit.X2,
	)

	G := crypto.GetG(curve)
	GxRv := crypto.MultiplyPoint(curve, &G, clientValidate.r)
	hServerModN := crypto.ModuloN(hServer, server.CurveParams.N)
	TxH := crypto.MultiplyPoint(curve, &server.UserRegistration.T, hServerModN)
	X1x := crypto.AddPoints(curve, GxRv, TxH)

	if !crypto.PointsEqual(curve, clientInit.X1, X1x) {
		return nil, errors.New("client authentication failed, X1 mismatch")
	}

	payload := &ServerAuthValidateResponsePayload{
		ServerKCTag: serverKCTag,
	}

	return &ServerAuthValidateResponse{
		Payload:          payload,
		RawServerKey:     rawServerKey,
		ServerSessionKey: serverSessionKey,
		ServerKCKey:      serverKCKey,
		HTranscript:      hServer,
	}, nil
}
