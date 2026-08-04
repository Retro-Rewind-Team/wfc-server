package gpcm

import (
	"errors"
	"os"
	"unicode/utf16"
	"wwfc/common"
)

var motdFilepath = "./motd.txt"
var motd string = ""

var (
	ErrEmptyMotd      = errors.New("motd cannot be empty")
	ErrMotdTooLong    = errors.New("motd is too long, max motd is 255 characters")
	ErrMotdB64TooLong = errors.New("motd is too long once encoded into base64")
)

func GetMessageOfTheDay() (string, error) {
	if motd == "" {
		contents, err := os.ReadFile(motdFilepath)
		if err != nil {
			return "", err
		}

		motd = string(contents)
	}

	return motd, nil
}

func encodeB64(motd string) string {
	motdUTF16 := utf16.Encode([]rune(motd))
	motdByteArray := common.UTF16ToByteArray(motdUTF16)
	return common.Base64DwcEncoding.EncodeToString(motdByteArray)
}

func GetMessageOfTheDayB64() (string, error) {
	// If GetMessageOfTheDay has not been called yet, we want to populate it
	// from motd.txt
	_, err := GetMessageOfTheDay()
	if err != nil {
		return "", err
	}

	return encodeB64(motd), nil
}

func SetMessageOfTheDay(nmotd string) error {
	if nmotd == "" {
		return ErrEmptyMotd
	}

	if len(nmotd) > 255 {
		return ErrMotdTooLong
	}

	// Limit of 1024-1 is imposed by the client for the encoded value
	if len(encodeB64(nmotd)) > 1023 {
		return ErrMotdB64TooLong
	}

	err := os.WriteFile(motdFilepath, []byte(nmotd), 0644)
	motd = nmotd

	return err
}
