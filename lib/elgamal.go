package lib

import (
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/random"

	"gopkg.in/dedis/cothority.v2"
)

// Encrypt performs the ElGamal encryption algorithm.
func Encrypt(public kyber.Point, message []byte) (K, C kyber.Point) {
	M := cothority.Suite.Point().Embed(message, random.New())

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := cothority.Suite.Scalar().Pick(random.New()) // ephemeral private key
	K = cothority.Suite.Point().Mul(k, nil)          // ephemeral DH public key
	S := cothority.Suite.Point().Mul(k, public)      // ephemeral DH shared secret
	C = S.Add(S, M)                                  // message blinded with secret
	return
}

// Decrypt performs the ElGamal decryption algorithm.
func Decrypt(private kyber.Scalar, K, C kyber.Point) kyber.Point {
	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := cothority.Suite.Point().Mul(private, K) // regenerate shared secret
	return cothority.Suite.Point().Sub(C, S)     // use to un-blind the message
}
