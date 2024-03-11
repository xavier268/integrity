package integrity

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestSignValid(t *testing.T) {

	data := []byte("FIRST PART" + reserve + "SECOND PART")
	fmt.Println("Data : ", string(data))
	fmt.Println("Delimiter :", string([]byte(reserve)[:delimSize]))

	if isValid(data, "password") {
		t.Error("should not be signed already")
	}
	sign(data, "password")
	fmt.Println("Signature performed")
	fmt.Println(string(data))

	if !isValid(data, "password") {
		t.Error("cannot confirm signature")
	}
	if isValid(data, "wrong password") {
		t.Error("should noyt accept invalid credentials")
	}

}

func TestGenerateRandomString(t *testing.T) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	data := make([]byte, payloadSize+80)
	for i := range data {
		data[i] = byte(rnd.Intn(256))
	}
	fmt.Printf("\n%#v\n", string(data))
}
