package owl

import (
	"github.com/GrzegorzManiak/GOWL/pkg/crypto"
	"math/big"
)

//
// -- Client to Server Messages
//

type RegistrationRequestPayload struct {
	U  string
	PI *big.Int
	T  []byte
}

type RegistrationRequest struct {
	Payload *RegistrationRequestPayload
	t       *big.Int
}

type ClientAuthInitRequestPayload struct {
	U   string
	X1  []byte
	X2  []byte
	PI1 *crypto.SchnorrZKP
	PI2 *crypto.SchnorrZKP
}

type ClientAuthInitRequest struct {
	Payload *ClientAuthInitRequestPayload
	x1      *big.Int
	x2      *big.Int
}

type ClientAuthValidateRequestPayload struct {
	ClientKCTag *big.Int
	Alpha       []byte
	PIAlpha     *crypto.SchnorrZKP
	R           *big.Int
}

type ClientAuthValidateRequest struct {
	Payload          *ClientAuthValidateRequestPayload
	RawClientKey     []byte
	ClientSessionKey *big.Int
	ClientKCKey      *big.Int
	HTranscript      *big.Int
}

//
// -- Server to Client Messages
//

type RegistrationResponsePayload struct {
	X3  []byte
	PI3 *crypto.SchnorrZKP
}

type RegistrationResponse struct {
	Payload *RegistrationResponsePayload
}

type ServerAuthInitResponsePayload struct {
	X3     []byte
	X4     []byte
	PI3    *crypto.SchnorrZKP
	PI4    *crypto.SchnorrZKP
	Beta   []byte
	PIBeta *crypto.SchnorrZKP
}

type ServerAuthInitResponse struct {
	Payload *ServerAuthInitResponsePayload
	Xx4     *big.Int
	GBeta   []byte
}

type ServerAuthValidateResponsePayload struct {
	ServerKCTag *big.Int
}

type ServerAuthValidateResponse struct {
	Payload          *ServerAuthValidateResponsePayload
	RawServerKey     []byte
	ServerSessionKey *big.Int
	ServerKCKey      *big.Int
	HTranscript      *big.Int
}
