package pkg

import (
	"crypto/ecdh"
	"math/big"
)

type SchnorrZKP struct {
	V *ecdh.PublicKey
	r *big.Int
}

/*
private void generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, String userID) {

Generate a random v from [1, n-1], and compute V = G*v
BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
n.subtract(BigInteger.ONE), new SecureRandom());
V = generator.multiply(v);

BigInteger h = getSHA256(generator, V, X, userID); // h

r = v.subtract(x.multiply(h)).mod(n); // r = v-x*h mod n
}
*/
