package main

import (
	"fmt"
	"log"
	"os"

	"github.com/fantasyczl/authcode/auth"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Printf("lack argument\n")
		return
	}

	secret := os.Args[1]
	code, err := auth.GetCode(secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(code)
}
