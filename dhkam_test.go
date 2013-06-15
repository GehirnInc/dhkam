package dhkam

import "bytes"
import "crypto/rand"
import "crypto/sha512"
import "fmt"
import "testing"

// Generating a shared key for AES256 with an HMAC-SHA512 requires 96
// bytes of keying material. This is the largest key likely to be in use,
// so we make sure we can at least generate this much key material.
const SharedKeySize = 96
const numTestCEK = 5 // number of test CEKs to generate

// TestSharedKey validates the computation of a shared key between two
// private keys. It generates two keys, computes the shared key between
// both pairs, and ensures that those two shared keys are the same.
func TestSharedKey(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	prv2, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}

	sk1, err := prv1.SharedKey(rand.Reader, &prv2.PublicKey, SharedKeySize)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	sk2, err := prv2.SharedKey(rand.Reader, &prv1.PublicKey, SharedKeySize)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}

	if !bytes.Equal(sk1, sk2) {
		fmt.Println("shared keys don't match")
		t.Fail()
	}
}

// TestImportPrivate generates a key, exports it, and reimports the key,
// verifying that it returns the same information.
func TestImportPrivate(t *testing.T) {
	prv, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}

	out := prv.ExportPrivate()
	prv1, err := ImportPrivate(rand.Reader, out)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	} else if prv.X.Cmp(prv1.X) != 0 {
		fmt.Println(ErrInvalidPrivateKey.Error())
		t.Fail()
	} else if prv.PublicKey.A.Cmp(prv1.PublicKey.A) != 0 {
		fmt.Println("dhkam: private key import failed.")
		t.Fail()
	}
}

// TestImportPublic generates a key, exports the public key, and reimports
// it, ensuring the two public keys match.
func TestImportPublic(t *testing.T) {
	prv, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out := prv.Export()
	pub, err := ImportPublic(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if pub.A.Cmp(prv.PublicKey.A) != 0 {
		fmt.Println("dhkam: import public key failed")
		t.FailNow()
	}
}

// TestKEK generates two private keys, computes a KEK from each, and
// generates a pair of lists of CEKs between each pair of private keys. It
// validates the uniqueness of those keys (i.e., the CEKs in a single
// list should be unique) and that the two lists are identical.
func TestKEK(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pub1 := &prv1.PublicKey
	pub2 := &prv2.PublicKey

	kek1 := prv1.InitializeKEK(rand.Reader, pub2, KEKAES256CBCHMACSHA512, nil, sha512.New())
	if kek1 == nil {
		fmt.Println("dhkam: failed to initialise KEK")
		t.FailNow()
	}
	kek2 := prv2.InitializeKEK(rand.Reader, pub1, KEKAES256CBCHMACSHA512, nil, sha512.New())
	if kek2 == nil {
		fmt.Println("dhkam: failed to initialise KEK")
		t.FailNow()
	}

	keyList1 := make([][]byte, numTestCEK)
	keyList2 := make([][]byte, numTestCEK)
	for i := 0; i < numTestCEK; i++ {
		keyList1[i], err = prv1.CEK(kek1)
		if err != nil {
			fmt.Println(err.Error())
			t.FailNow()
		}
		keyList2[i], err = prv2.CEK(kek2)
		if err != nil {
			fmt.Println(err.Error())
			t.FailNow()
		}
	}

	for i := 0; i < numTestCEK; i++ {
		for j := 0; j < numTestCEK; j++ {
			if i == j {
				continue
			}
			if bytes.Equal(keyList1[i], keyList1[j]) {
				fmt.Println("dhkam: CEK isn't unique")
				t.FailNow()
			}
			if bytes.Equal(keyList2[i], keyList2[j]) {
				fmt.Println("dhkam: CEK isn't unique")
				t.FailNow()
			}
		}
	}

	for i := 0; i < numTestCEK; i++ {
		if !bytes.Equal(keyList1[i], keyList2[i]) {
			fmt.Println("dhkam: CEK's don't match")
			t.FailNow()
		}
	}
}

// Benchmark the generate of private keys.
func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

// Benchmark the computation of shared keys.
func BenchmarkSharedKey(b *testing.B) {
	prv1, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}
	prv2, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, err := prv1.SharedKey(rand.Reader, &prv2.PublicKey, SharedKeySize)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}

}

// Benchmark the generation of CEKs.
func BenchmarkCEKGeneration(b *testing.B) {
	prv1, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}
	prv2, err := GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}
	kek := prv1.InitializeKEK(rand.Reader, &prv2.PublicKey,
		KEKAES256CBCHMACSHA512, nil, sha512.New())
	if kek == nil {
		fmt.Println("dhkam: failed to generate KEK")
		b.FailNow()
	}

	for i := 0; i < b.N; i++ {
		_, err := prv1.CEK(kek)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}

}
