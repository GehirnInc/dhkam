package dhkam

import "bytes"
import "crypto/rand"
import "fmt"
import "testing"

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

	sk1, err := prv1.GenerateSharedKey(rand.Reader, &prv2.PublicKey, 32)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	sk2, err := prv2.GenerateSharedKey(rand.Reader, &prv1.PublicKey, 32)
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
