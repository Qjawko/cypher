package main

import "fmt"

func main() {
	if err := GenPrivateKey(); err != nil {
		if err == ErrPrivateKeyAlreadyExists {
			fmt.Println("приватный ключ уже создан")
		} else {
			panic(err)
		}
	}

	if err := GenPublicKey(); err != nil {
		if err == ErrPublicKeyAlreadyExists {
			fmt.Println("публичный ключ уже создан")
		} else {
			panic(err)
		}
	}

	// тут живет структура, которая будет зашифрована
	data := DataPayload{
		A:    1,
		B:    2,
		Text: "мазафака",
	}

	payload, err := GenPayload(&data)
	if err != nil {
		panic(err)
	}

	fmt.Println("сгенерирован payload:", payload)

	v, err := ValidatePayload([]byte(payload))
	if err != nil {
		panic(err)
	}

	fmt.Println("оригинальный payload: ", string(v))
}
