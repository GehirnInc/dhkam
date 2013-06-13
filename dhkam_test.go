package dhkam

import "bytes"
import "crypto/rand"
import "crypto/sha256"
import "fmt"
import "testing"

// Generating a shared key for AES256 with an HMAC-SHA512 requires 96
// bytes of keying material.
const SharedKeySize = 96

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
	}
}

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

	kek := InitialiseKEK(AES256CBC, SharedKeySize, nil)
	if kek == nil {
		fmt.Println("dhkam: failed to initialise KEK")
		t.FailNow()
	}

	pub := &prv2.PublicKey

	keyList := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		h := sha256.New()
		keyList[i], err = prv1.KEK(rand.Reader, pub, kek, h)
		if err != nil {
			fmt.Println(err.Error())
			t.FailNow()
		}
	}

	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if i == j {
				continue
			}
			if bytes.Equal(keyList[i], keyList[j]) {
				fmt.Println("dhkam: CEK isn't unique")
				t.FailNow()
			}
		}
	}
}
