package owl

import (
	"github.com/GrzegorzManiak/GOWL/pkg/crypto"
	"math/big"
)

//
// -- Client to Server Messages
//

type RegistrationRequestPayload struct {
	U string
	π *big.Int
	T []byte
}

type RegistrationRequest struct {
	Payload *RegistrationRequestPayload
	t       *big.Int
}

type ClientAuthInitRequestPayload struct {
	UserIdentifier string
	X1             []byte
	X2             []byte
	Π1             *crypto.SchnorrZKP
	Π2             *crypto.SchnorrZKP
}

type ClientAuthInitRequest struct {
	Payload *ClientAuthInitRequestPayload
	x1      *big.Int
	x2      *big.Int
}

type ClientAuthValidateRequestPayload struct {
	ClientKCTag *big.Int
	α           []byte
	Πα          *crypto.SchnorrZKP
	r           *big.Int
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
	X3 []byte
	Π3 *crypto.SchnorrZKP
}

type RegistrationResponse struct {
	Payload *RegistrationResponsePayload
}

type ServerAuthInitResponsePayload struct {
	X3 []byte
	X4 []byte
	Π3 *crypto.SchnorrZKP
	Π4 *crypto.SchnorrZKP
	β  []byte
	Πβ *crypto.SchnorrZKP
}

type ServerAuthInitResponse struct {
	Payload *ServerAuthInitResponsePayload
	x4      *big.Int
	Gβ      []byte
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
