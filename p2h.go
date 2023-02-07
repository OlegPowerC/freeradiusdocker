package main

import (
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

func GenerateSalt(digitcount uint) (Salt []byte, err error) {
	if digitcount < 16 || digitcount > 32 {
		return nil, fmt.Errorf("Wrong Salt len: %d , len must be betwen 16 and 32", digitcount)
	}
	var Sl []byte
	rand.Seed(time.Now().UnixNano())
	for a := 0; a < int(digitcount); a++ {
		Byte1 := byte(rand.Uint32())
		Sl = append(Sl, Byte1)
	}
	return Sl, nil
}

func main() {
	PassString := flag.String("p", "", "Password string")
	HashType := flag.String("t", "Type of the encrypted password string", "sha or ssha")
	flag.Parse()
	if len(*PassString) < 3 {
		fmt.Println("Password lenght must be leash of 4 characters")
		os.Exit(1)
	}

	Base64PassString := ""
	PassTypeString := "SHA-Password"
	PassTypeFreeRadiusString := ""

	PassBytes := []byte(strings.TrimSpace(*PassString))
	hsm := sha1.New()

	PassEncType := strings.ToLower(strings.TrimSpace(*HashType))
	switch PassEncType {
	case "sha":
		//Просто берем SHA1 хэш от пароля
		hsm.Write(PassBytes)
		hc := hsm.Sum(nil)
		Base64PassString = base64.StdEncoding.EncodeToString(hc)
		PassTypeFreeRadiusString = fmt.Sprintf("%s := \"%s\"", PassTypeString, Base64PassString)
		fmt.Println(PassTypeFreeRadiusString)
		os.Exit(0)
	case "ssha":
		//Создаем "соль" - набор случайных байт - например 16
		Salt, _ := GenerateSalt(16)
		FullDataToEncode := PassBytes
		//Создаем массив байт состоящий из пароля и сразу за ним нашей "соли"
		FullDataToEncode = append(FullDataToEncode, Salt...)
		//Теперь получаем от этого массива хэш sha1
		hsm.Write(FullDataToEncode)
		hc := hsm.Sum(nil)
		FullPassForHash := hc
		//Затем создаем массив в который помещаем полученный Хэш и дополняем его нашей "солью"
		FullPassForHash = append(FullPassForHash, Salt...)
		//Тепеь этот массив кодируем в Base64
		Base64PassString = base64.StdEncoding.EncodeToString(FullPassForHash)
		PassTypeString = "SSHA-Password"
		PassTypeFreeRadiusString = fmt.Sprintf("%s := \"%s\"", PassTypeString, Base64PassString)
		fmt.Println(PassTypeFreeRadiusString)
		os.Exit(0)
	default:
		fmt.Println("Please provide valid encryption tupe: sha or ssha")
	}
}
