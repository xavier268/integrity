package util

import (
	"fmt"
	"testing"
)

func TestSignValid(t *testing.T) {

	data := []byte("FIRST PART" + reserve + "SECOND PART")
	fmt.Println("Data : ", string(data))
	fmt.Println("Delimiter :", string([]byte(reserve)[:delimSize]))

	if isValid(data) {
		t.Error("should not be signed already")
	}
	sign(data)
	fmt.Println("Signature performed")
	fmt.Println(string(data))

	if !isValid(data) {
		t.Error("cannot confirm signature")
	}

}
