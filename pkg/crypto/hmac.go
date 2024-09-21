package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
)

func DeriveHMACTag(
	key *big.Int,
	messageString string,
	senderID string,
	receiverID string,
	senderKey1 []byte,
	senderKey2 []byte,
	receiverKey1 []byte,
	receiverKey2 []byte,
) *big.Int {
	keyBytes := key.Bytes()
	mac := hmac.New(sha256.New, keyBytes)

	mac.Write([]byte(messageString))
	mac.Write([]byte(senderID))
	mac.Write([]byte(receiverID))
	mac.Write(senderKey1)
	mac.Write(senderKey2)
	mac.Write(receiverKey1)
	mac.Write(receiverKey2)

	hmacSum := mac.Sum(nil)
	hmacBigInt := new(big.Int).SetBytes(hmacSum)

	return hmacBigInt
}
