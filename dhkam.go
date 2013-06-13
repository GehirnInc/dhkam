package dhkam

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
)

const (
	lenPriv = 32
	lenPub  = 256
)

var (
	ErrBlindingFailed    = fmt.Errorf("dhkam: blinding failed")
	ErrInvalidKEKParams  = fmt.Errorf("dhkam: invalid KEK parameters")
	ErrInvalidPrivateKey = fmt.Errorf("dhkam: invalid private key")
	ErrInvalidPublicKey  = fmt.Errorf("dhkam: invalid public key")
	ErrInvalidSharedKey  = fmt.Errorf("dhkam: invalid shared key")
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

// GeneratePublic is used to regenerate the public key for the private key.
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

	bx.Sub(bx, blinding)
	r1 := new(big.Int).Exp(a, blinding, P)
	r2 := new(big.Int).Exp(a, bx, P)
	y = new(big.Int).Mul(r1, r2)
	y.Mod(y, P)

	if y.BitLen() > P.BitLen() {
		y = nil
		err = ErrBlindingFailed
		return
	}
	return
}

// GenerateSharedKey returns a shared key from a private and public key
// suitable for use in symmetric encryption.
func (prv *PrivateKey) SharedKey(prng io.Reader, pub *PublicKey, size int) (sk []byte, err error) {
	if !pub.Valid() {
		err = ErrInvalidPublicKey
		return
	}
	skBig, err := blind(prng, pub.A, prv.X)
	if err != nil {
		return
	}
	sk = skBig.Bytes()[:size]
	if len(sk) < size {
		err = ErrInvalidSharedKey
	}
	return
}

// ASN.1 definitions for a few algorithms
var (
	AES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 1, 2}
	AES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 1, 6}
	AES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 1, 22}
	AES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 1, 26}
	AES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 1, 42}
	AES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 1, 46}
)

type KEKParams struct {
	KeySpecificInfo KeySpecificInfo
	PartyAInfo      []byte `asn1:"optional"`
	SuppPubInfo     []byte
}

type KeySpecificInfo struct {
	Algorithm asn1.ObjectIdentifier
	counter   []byte
}

func (kek *KEKParams) KeyLen() int {
	var keylen32 uint32
	buf := bytes.NewBuffer(kek.SuppPubInfo)

	err := binary.Read(buf, binary.BigEndian, &keylen32)
	if err != nil {
		return 0
	}

	return int(keylen32)
}

func incCounter(counter []byte) {
	if counter[3]++; counter[3] != 0 {
		return
	} else if counter[2]++; counter[2] != 0 {
		return
	} else if counter[1]++; counter[1] != 0 {
		return
	} else {
		counter[0]++
		return
	}
}

func InitialiseKEK(algorithm asn1.ObjectIdentifier, keylen int, ainfo []byte) *KEKParams {
	if ainfo != nil && len(ainfo) != 64 {
		return nil
	}

	keylen32 := uint32(keylen)
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, keylen32); err != nil {
		return nil
	}

	var kek KEKParams

	kek.SuppPubInfo = buf.Bytes()
	kek.KeySpecificInfo.Algorithm = algorithm
	kek.KeySpecificInfo.counter = []byte{0, 0, 0, 1}
	kek.PartyAInfo = ainfo
	return &kek
}

func (prv *PrivateKey) CEK(rand io.Reader, pub *PublicKey, kek *KEKParams, hash hash.Hash) (key []byte, err error) {
	var keylen int
	if kek == nil {
		return nil, ErrInvalidKEKParams
	} else if keylen = kek.KeyLen(); keylen == 0 {
		return nil, ErrInvalidKEKParams
	}

	otherInfo, err := asn1.Marshal(*kek)
	if err != nil {
		return
	}

	zz, err := prv.SharedKey(rand, pub, keylen)
	if err != nil {
		return
	}
	zz = leftPad(zz, 256)

	blocks := ((keylen + 7) * 8) / (hash.Size() * 8)

	key = make([]byte, 0, keylen)
	for i := 0; i < blocks; i++ {
		hash.Write(zz)
		hash.Write(otherInfo)
		key = append(key, hash.Sum(nil)...)
		hash.Reset()
		incCounter(kek.KeySpecificInfo.counter)
	}
	key = key[:keylen]
	return
}

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
