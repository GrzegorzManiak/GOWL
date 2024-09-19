package pkg

import (
	"crypto/ecdh"
	"crypto/sha256"
	"math/big"
	"reflect"
)

func IntTo4Bytes(i int) []byte {
	return []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}

func Hash(args ...interface{}) *big.Int {
	sha256Output := sha256.New()

	for _, arg := range args {
		switch v := arg.(type) {

		case *ecdh.PublicKey:
			encoded := v.Bytes()
			sha256Output.Write(IntTo4Bytes(len(encoded)))
			sha256Output.Write(encoded)

		case []byte:
			sha256Output.Write(IntTo4Bytes(len(v)))
			sha256Output.Write(v)

		case string:
			bytes := []byte(v)
			sha256Output.Write(IntTo4Bytes(len(bytes)))
			sha256Output.Write(bytes)

		case *big.Int:
			i := v.Bytes()
			// I had the painfull joy of figuring out that in java, when
			// why convert a big int into a byte array, the first byte is
			// a sign byte. Adleast that's my guess.
			if i[0] >= 128 {
				i = append([]byte{0}, i...)
			} else {
				i = append([]byte{1}, i...)
			}
			sha256Output.Write(IntTo4Bytes(len(i)))
			sha256Output.Write(i)

		case SchnorrZKP:
			vEncoded := v.V
			rBytes := v.R.Bytes()
			sha256Output.Write(IntTo4Bytes(len(vEncoded)))
			sha256Output.Write(vEncoded)
			sha256Output.Write(IntTo4Bytes(len(rBytes)))
			sha256Output.Write(rBytes)

		default:
			panic("Invalid type passed to Hash" + reflect.TypeOf(v).String())
		}
	}

	hash := sha256Output.Sum(nil)
	return new(big.Int).SetBytes(hash[:])
}
