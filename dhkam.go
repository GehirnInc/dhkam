package dhkam

import (
	"fmt"
	"io"
	"math/big"
)

const (
	lenPriv = 32
	lenPub  = 256
)

var (
	ErrBlindingFailed    = fmt.Errorf("dhkam: blinding failed")
	ErrInvalidPrivateKey = fmt.Errorf("dhkam: invalid private key")
	ErrInvalidPublicKey  = fmt.Errorf("dhkam: invalid public key")
)

type PublicKey struct {
	A *big.Int
}

// ImportPublic takes a byte slice and attempts to convert it to a public
// key, checking to make sure it's a valid key.
func ImportPublic(in []byte) (pub *PublicKey, err error) {
	pub = new(PublicKey)
	pub.A = new(big.Int).SetBytes(in)
	if !pub.Valid() {
		return nil, ErrInvalidPublicKey
	}
	return
}

// Valid runs sanity checks on the public key to ensure it is valid.
func (pub *PublicKey) Valid() bool {
	if pub.A.BitLen() > P.BitLen() {
		return false
	}
	return true
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

// Export returns a byte slice representation of the public key.
func (prv *PrivateKey) Export() []byte {
	if prv == nil || prv.PublicKey.A == nil {
		return nil
	}
	return prv.PublicKey.A.Bytes()
}

// ExportPrivate returns a byte slice representation of the private key.
func (prv *PrivateKey) ExportPrivate() []byte {
	if prv == nil {
		return nil
	}
	return prv.X.Bytes()
}

//
func (prv *PrivateKey) GeneratePublic(prng io.Reader) (err error) {
	if prv == nil {
		return ErrInvalidPrivateKey
	}
	prv.PublicKey, err = generatePublicKey(prng, prv.X)
	return
}

// ImportPrivate loads a byte slice into a private key and regenerates the
// public key for it.
func ImportPrivate(prng io.Reader, in []byte) (prv *PrivateKey, err error) {
	prv = new(PrivateKey)
	prv.X = new(big.Int).SetBytes(in)
	err = prv.GeneratePublic(prng)
	return
}

// GenerateKey generates a new key pair.
func GenerateKey(prng io.Reader) (prv *PrivateKey, err error) {
	x := make([]byte, lenPriv)
	_, err = io.ReadFull(prng, x)
	if err != nil {
		return
	}
	X := new(big.Int).SetBytes(x)
	if X.Cmp(bigZero) != 1 {
		return GenerateKey(prng)
	} else if X.Cmp(new(big.Int).Sub(P, bigOne)) == 1 {
		return GenerateKey(prng)
	}
	prv = new(PrivateKey)
	prv.X = X
	prv.PublicKey, err = generatePublicKey(prng, prv.X)
	if err == nil {
		if !(&prv.PublicKey).Valid() {
			err = ErrInvalidPublicKey
		}
	}
	return
}

func generatePublicKey(prng io.Reader, x *big.Int) (pub PublicKey, err error) {
	pub.A, err = blind(prng, g, x)
	if err == nil && !(&pub).Valid() {
		err = ErrInvalidPublicKey
	}
	return
}

// randBigInt returns a random big.Int within the requested size in bits.
func randBigInt(prng io.Reader, size int) (r *big.Int, err error) {
	bs := make([]byte, size/8)
	_, err = io.ReadFull(prng, bs)
	if err != nil {
		return
	}
	r = new(big.Int).SetBytes(bs)
	return
}

// Blinding carries out modular blinding for the operation
//   y = a ^ x mod p
// The modulus is fixed for DHKAM over group 14, so the caller needs
// only to pass in the a and x values.
func blind(prng io.Reader, a, x *big.Int) (y *big.Int, err error) {
	bx := new(big.Int).Add(big2To258, x)

	r, err := randBigInt(prng, lenPub)
	if err != nil {
		err = ErrBlindingFailed
		return
	}
	blinding := new(big.Int).Add(big2To256, r)

	blindX := new(big.Int).Sub(bx, blinding)
	r1 := new(big.Int).Exp(a, blinding, P)
	r2 := new(big.Int).Exp(a, blindX, P)
	r1.Mul(r1, r2)
	r1.Mod(r1, P)

	if r1.BitLen() > P.BitLen() {
		err = ErrBlindingFailed
		return
	}
	y = r1
	return
}

// GenerateSharedKey returns
func (prv *PrivateKey) GenerateSharedKey(prng io.Reader, pub *PublicKey, size int) (sk []byte, err error) {
	if !pub.Valid() {
		err = ErrInvalidPublicKey
		return
	}
	skBig, err := blind(prng, pub.A, prv.X)
	if err != nil {
		return
	}
	sk = skBig.Bytes()[:size]
	return
}
