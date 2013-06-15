/*
	dhkam implements the Diffie Hellman Key Agreement Method using
	the RFC 3526 Group 14 modulus, and uses blinded key generation.

	The package supports using the shared key as a static key, and
	using the shared key to compute a KEK, implementing the system
	described in RFC 2631.

	The shared key may be retrieved using the SharedKey method. A
	KEK must first be initialised using the InitializeKEK function,
	which returns a set of KEK paramaters stored in a KEK type. This
	can be combined with the `CEK` method on private keys to derive
	an appropriate CEK.

	For example, to generate a KEK for use with AES128CBC with an
	HMAC-SHA256 MAC:

		prv, err := dhkam.GenerateKey(rand.Reader)
		if err != nil {
			// ...
		}

		// pub is a *dhkam.PublicKey containing the public key
		// of the party for whom we share this KEK.
		kek := prv.InitializeKEK(rand.Reader, pub,
			dhkam.KEKAES128CBCHMACSHA256, nil, sha256.New())
		if kek == nil {
			// an error occurred while initialising the KEK.
		}

	We can generate a CEK from this with:

		key, err := prv.CEK(kek)
		if err != nil {
			// ...
		}
			
		aesKey := key[:16]	// 16 bytes is AES-128 key length.
		hmacKey := key[16:]	// the rest of the key is the HMAC key.
*/
package dhkam
