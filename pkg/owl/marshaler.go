package owl

import (
	"encoding/json"
	"github.com/GrzegorzManiak/GOWL/pkg/crypto"
)

func (payload *RegistrationRequestPayload) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		U  string `json:"U"`
		PI string `json:"PI"`
		T  string `json:"T"`
	}{
		U:  payload.U,
		PI: crypto.B64Encode(payload.PI),
		T:  crypto.B64Encode(payload.T),
	})
}

func (payload *RegistrationRequestPayload) Unmarshal(data []byte) error {
	var aux struct {
		U  string `json:"U"`
		PI string `json:"PI"`
		T  string `json:"T"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.U = aux.U
	payload.PI = crypto.B64DecodeBigInt(aux.PI)
	payload.T = crypto.B64DecodeBytes(aux.T)

	return nil
}

func (payload *RegistrationRequest) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		Payload *RegistrationRequestPayload `json:"Payload"`
		t       string                      `json:"t"`
	}{
		Payload: payload.Payload,
		t:       crypto.B64Encode(payload.t),
	})
}

func (payload *RegistrationRequest) Unmarshal(data []byte) error {
	var aux struct {
		Payload *RegistrationRequestPayload `json:"Payload"`
		t       string                      `json:"t"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.Payload = aux.Payload
	payload.t = crypto.B64DecodeBigInt(aux.t)

	return nil
}

func (payload *ClientAuthInitRequestPayload) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		UserIdentifier string `json:"UserIdentifier"`
		X1             string `json:"X1"`
		X2             string `json:"X2"`
		PI1_V          string `json:"PI1_V"`
		PI1_R          string `json:"PI1_R"`
		PI2_V          string `json:"PI2_V"`
		PI2_R          string `json:"PI2_R"`
	}{
		UserIdentifier: payload.U,
		X1:             crypto.B64Encode(payload.X1),
		X2:             crypto.B64Encode(payload.X2),
		PI1_V:          crypto.B64Encode(payload.PI1.V),
		PI1_R:          crypto.B64Encode(payload.PI1.R),
		PI2_V:          crypto.B64Encode(payload.PI2.V),
		PI2_R:          crypto.B64Encode(payload.PI2.R),
	})
}

func (payload *ClientAuthInitRequestPayload) Unmarshal(data []byte) error {
	var aux struct {
		UserIdentifier string `json:"UserIdentifier"`
		X1             string `json:"X1"`
		X2             string `json:"X2"`
		PI1_V          string `json:"PI1_V"`
		PI1_R          string `json:"PI1_R"`
		PI2_V          string `json:"PI2_V"`
		PI2_R          string `json:"PI2_R"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.U = aux.UserIdentifier
	payload.X1 = crypto.B64DecodeBytes(aux.X1)
	payload.X2 = crypto.B64DecodeBytes(aux.X2)

	payload.PI1 = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.PI1_V),
		R: crypto.B64DecodeBigInt(aux.PI1_R),
	}

	payload.PI2 = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.PI2_V),
		R: crypto.B64DecodeBigInt(aux.PI2_R),
	}

	return nil
}

func (payload *ClientAuthInitRequest) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		Payload *ClientAuthInitRequestPayload `json:"Payload"`
		x1      string                        `json:"x1"`
		x2      string                        `json:"x2"`
	}{
		Payload: payload.Payload,
		x1:      crypto.B64Encode(payload.x1),
		x2:      crypto.B64Encode(payload.x2),
	})
}

func (payload *ClientAuthInitRequest) Unmarshal(data []byte) error {
	var aux struct {
		Payload *ClientAuthInitRequestPayload `json:"Payload"`
		x1      string                        `json:"x1"`
		x2      string                        `json:"x2"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.Payload = aux.Payload
	payload.x1 = crypto.B64DecodeBigInt(aux.x1)
	payload.x2 = crypto.B64DecodeBigInt(aux.x2)

	return nil
}

func (payload *ClientAuthValidateRequestPayload) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		ClientKCTag string `json:"ClientKCTag"`
		Alpha       string `json:"Alpha"`
		PIAlpha_V   string `json:"PIAlpha_V"`
		PIAlpha_R   string `json:"PIAlpha_R"`
		R           string `json:"R"`
	}{
		ClientKCTag: crypto.B64Encode(payload.ClientKCTag),
		Alpha:       crypto.B64Encode(payload.Alpha),
		PIAlpha_V:   crypto.B64Encode(payload.PIAlpha.V),
		PIAlpha_R:   crypto.B64Encode(payload.PIAlpha.R),
		R:           crypto.B64Encode(payload.r),
	})
}

func (payload *ClientAuthValidateRequestPayload) Unmarshal(data []byte) error {
	var aux struct {
		ClientKCTag string `json:"ClientKCTag"`
		Alpha       string `json:"Alpha"`
		PIAlpha_V   string `json:"PIAlpha_V"`
		PIAlpha_R   string `json:"PIAlpha_R"`
		R           string `json:"R"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.ClientKCTag = crypto.B64DecodeBigInt(aux.ClientKCTag)
	payload.Alpha = crypto.B64DecodeBytes(aux.Alpha)

	payload.PIAlpha = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.PIAlpha_V),
		R: crypto.B64DecodeBigInt(aux.PIAlpha_R),
	}

	payload.r = crypto.B64DecodeBigInt(aux.R)

	return nil
}

func (payload *ClientAuthValidateRequest) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		Payload          *ClientAuthValidateRequestPayload `json:"Payload"`
		RawClientKey     string                            `json:"RawClientKey"`
		ClientSessionKey string                            `json:"ClientSession"`
		ClientKCKey      string                            `json:"ClientKCKey"`
		HTranscript      string                            `json:"HTranscript"`
	}{
		Payload:          payload.Payload,
		RawClientKey:     crypto.B64Encode(payload.RawClientKey),
		ClientSessionKey: crypto.B64Encode(payload.ClientSessionKey),
		ClientKCKey:      crypto.B64Encode(payload.ClientKCKey),
		HTranscript:      crypto.B64Encode(payload.HTranscript),
	})
}

func (payload *ClientAuthValidateRequest) Unmarshal(data []byte) error {
	var aux struct {
		Payload          *ClientAuthValidateRequestPayload `json:"Payload"`
		RawClientKey     string                            `json:"RawClientKey"`
		ClientSessionKey string                            `json:"ClientSession"`
		ClientKCKey      string                            `json:"ClientKCKey"`
		HTranscript      string                            `json:"HTranscript"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.Payload = aux.Payload
	payload.RawClientKey = crypto.B64DecodeBytes(aux.RawClientKey)
	payload.ClientSessionKey = crypto.B64DecodeBigInt(aux.ClientSessionKey)
	payload.ClientKCKey = crypto.B64DecodeBigInt(aux.ClientKCKey)
	payload.HTranscript = crypto.B64DecodeBigInt(aux.HTranscript)

	return nil
}

func (payload *RegistrationResponsePayload) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		X3    string `json:"X3"`
		PI3_V string `json:"PI3_V"`
		PI3_R string `json:"PI3_R"`
	}{
		X3:    crypto.B64Encode(payload.X3),
		PI3_V: crypto.B64Encode(payload.PI3.V),
		PI3_R: crypto.B64Encode(payload.PI3.R),
	})
}

func (payload *RegistrationResponsePayload) Unmarshal(data []byte) error {
	var aux struct {
		X3    string `json:"X3"`
		PI3_V string `json:"PI3_V"`
		PI3_R string `json:"PI3_R"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.X3 = crypto.B64DecodeBytes(aux.X3)

	payload.PI3 = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.PI3_V),
		R: crypto.B64DecodeBigInt(aux.PI3_R),
	}

	return nil
}

func (payload *ServerAuthInitResponsePayload) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		X3       string `json:"X3"`
		X4       string `json:"X4"`
		Pi3_V    string `json:"Pi3_V"`
		Pi3_R    string `json:"Pi3_R"`
		Pi4_V    string `json:"Pi4_V"`
		Pi4_R    string `json:"Pi4_R"`
		Beta     string `json:"Beta"`
		PIBeta_V string `json:"PIBeta_V"`
		PIBeta_R string `json:"PIBeta_R"`
	}{
		X3:       crypto.B64Encode(payload.X3),
		X4:       crypto.B64Encode(payload.X4),
		Pi3_V:    crypto.B64Encode(payload.PI3.V),
		Pi3_R:    crypto.B64Encode(payload.PI3.R),
		Pi4_V:    crypto.B64Encode(payload.PI4.V),
		Pi4_R:    crypto.B64Encode(payload.PI4.R),
		Beta:     crypto.B64Encode(payload.Beta),
		PIBeta_V: crypto.B64Encode(payload.PIBeta.V),
		PIBeta_R: crypto.B64Encode(payload.PIBeta.R),
	})
}

func (payload *ServerAuthInitResponsePayload) Unmarshal(data []byte) error {
	var aux struct {
		X3       string `json:"X3"`
		X4       string `json:"X4"`
		Pi3_V    string `json:"Pi3_V"`
		Pi3_R    string `json:"Pi3_R"`
		Pi4_V    string `json:"Pi4_V"`
		Pi4_R    string `json:"Pi4_R"`
		Beta     string `json:"Beta"`
		PIBeta_V string `json:"PIBeta_V"`
		PIBeta_R string `json:"PIBeta_R"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.X3 = crypto.B64DecodeBytes(aux.X3)
	payload.X4 = crypto.B64DecodeBytes(aux.X4)

	payload.PI3 = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.Pi3_V),
		R: crypto.B64DecodeBigInt(aux.Pi3_R),
	}

	payload.PI4 = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.Pi4_V),
		R: crypto.B64DecodeBigInt(aux.Pi4_R),
	}

	payload.Beta = crypto.B64DecodeBytes(aux.Beta)

	payload.PIBeta = &crypto.SchnorrZKP{
		V: crypto.B64DecodeBytes(aux.PIBeta_V),
		R: crypto.B64DecodeBigInt(aux.PIBeta_R),
	}

	return nil
}

func (payload *ServerAuthInitResponse) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		Payload *ServerAuthInitResponsePayload `json:"Payload"`
		x4      string                         `json:"x4"`
		GBeta   string                         `json:"GBeta"`
	}{
		Payload: payload.Payload,
		x4:      crypto.B64Encode(payload.x4),
		GBeta:   crypto.B64Encode(payload.GBeta),
	})
}

func (payload *ServerAuthInitResponse) Unmarshal(data []byte) error {
	var aux struct {
		Payload *ServerAuthInitResponsePayload `json:"Payload"`
		x4      string                         `json:"x4"`
		GBeta   string                         `json:"GBeta"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.Payload = aux.Payload
	payload.x4 = crypto.B64DecodeBigInt(aux.x4)
	payload.GBeta = crypto.B64DecodeBytes(aux.GBeta)

	return nil
}

func (payload *ServerAuthValidateResponsePayload) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		ServerKCTag string `json:"ServerKCTag"`
	}{
		ServerKCTag: crypto.B64Encode(payload.ServerKCTag),
	})
}

func (payload *ServerAuthValidateResponsePayload) Unmarshal(data []byte) error {
	var aux struct {
		ServerKCTag string `json:"ServerKCTag"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.ServerKCTag = crypto.B64DecodeBigInt(aux.ServerKCTag)

	return nil
}

func (payload *ServerAuthValidateResponse) Marshal() ([]byte, error) {
	return json.Marshal(&struct {
		Payload          *ServerAuthValidateResponsePayload `json:"Payload"`
		RawServerKey     string                             `json:"RawServerKey"`
		ServerSessionKey string                             `json:"ServerSession"`
		ServerKCKey      string                             `json:"ServerKCKey"`
		HTranscript      string                             `json:"HTranscript"`
	}{
		Payload:          payload.Payload,
		RawServerKey:     crypto.B64Encode(payload.RawServerKey),
		ServerSessionKey: crypto.B64Encode(payload.ServerSessionKey),
		ServerKCKey:      crypto.B64Encode(payload.ServerKCKey),
		HTranscript:      crypto.B64Encode(payload.HTranscript),
	})
}

func (payload *ServerAuthValidateResponse) Unmarshal(data []byte) error {
	var aux struct {
		Payload          *ServerAuthValidateResponsePayload `json:"Payload"`
		RawServerKey     string                             `json:"RawServerKey"`
		ServerSessionKey string                             `json:"ServerSession"`
		ServerKCKey      string                             `json:"ServerKCKey"`
		HTranscript      string                             `json:"HTranscript"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	payload.Payload = aux.Payload
	payload.RawServerKey = crypto.B64DecodeBytes(aux.RawServerKey)
	payload.ServerSessionKey = crypto.B64DecodeBigInt(aux.ServerSessionKey)
	payload.ServerKCKey = crypto.B64DecodeBigInt(aux.ServerKCKey)
	payload.HTranscript = crypto.B64DecodeBigInt(aux.HTranscript)

	return nil
}
