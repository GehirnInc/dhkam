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
*/
package dhkam
