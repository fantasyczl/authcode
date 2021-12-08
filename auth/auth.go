// This is for handling Google Authenticator 2-factor authentication.
package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const codeLengthDefault = 6

func GetCode(secret string) (string, error) {
	timeSlice := uint32(time.Now().Unix() / 30)
	return GetCodeWithTimeSlice(secret, timeSlice)
}

// Calculate the code, with given secret and point in time.
func GetCodeWithTimeSlice(secret string, timeSlice uint32) (string, error) {
	timeBytes := encodeTime(timeSlice)
	secretKey, err := base32Decode(secret)
	if err != nil {
		return "", err
	}

	// Hash it with users secret key
	h := hmac.New(sha1.New, secretKey)
	h.Write(timeBytes)
	hm := h.Sum(nil)

	// Use last nipple of result as index/offset
	offset := hm[len(hm)-1] & 0x0F
	// grab 4 bytes of the result
	hashpart := hm[offset : offset+4]

	// Unpak binary value
	value := binary.BigEndian.Uint32(hashpart)
	value = value & 0x7FFFFFFF

	module := uint32(math.Pow10(codeLengthDefault))
	v := value % module
	return strPadFromLeft(int(v), codeLengthDefault, '0'), nil
}

func encodeTime(timeSlice uint32) []byte {
	if timeSlice == 0 {
		timeSlice = uint32(time.Now().Unix() / 30)
	}

	// Pack time into binary string
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, timeSlice)

	timeBigEnd := binary.BigEndian.Uint32(bs)
	timeStr := make([]byte, 8)
	for i := 0; i < 4; i++ {
		timeStr[4+i] = byte(timeBigEnd & 0xFF)
		timeBigEnd >>= 8
	}

	return timeStr
}

func strPadFromLeft(v, length int, padChar byte) string {
	s := strconv.FormatInt(int64(v), 10)
	if len(s) < length {
		diff := length - len(s)
		for i := 0; i < diff; i++ {
			s = string(padChar) + s
		}
	}

	return s
}

// decode base32.
func base32Decode(secret string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("secret is empty")
	}

	base32chars := getBase32LookupTable()
	base32charsFlipped := make(map[byte]int, len(base32chars))
	for i, b := range base32chars {
		base32charsFlipped[b] = i
	}

	paddingCharCount := getByteCountInString(secret, base32chars[32])
	allowedValues := []int{6, 4, 3, 1, 0}

	isValidCnt := false
	for i := range allowedValues {
		if allowedValues[i] == paddingCharCount {
			isValidCnt = true
			break
		}
	}

	if !isValidCnt {
		return nil, errors.New("invalid padding char count")
	}

	for i := 0; i < 4; i++ {
		if paddingCharCount == allowedValues[i] {
			for j := len(secret) - allowedValues[i]; j < len(secret); j++ {
				if secret[j] != base32chars[32] {
					return nil, errors.New("invalid padding char")
				}
			}
		}
	}

	secretNew := strings.ReplaceAll(secret, "=", "")
	secretList := []byte(secretNew)

	binaries := make([]byte, 0, len(secret))
	for i := 0; i < len(secretList); i = i + 8 {
		if _, ok := base32charsFlipped[secretList[i]]; !ok {
			return nil, errors.New("invalid char in secret")
		}

		x := ""
		for j := 0; j < 8; j++ {
			bStr := "0"
			byteNum := 0
			if i+j < len(secretList) {
				byteNum = base32charsFlipped[secretList[i+j]]
				bStr = strconv.FormatInt(int64(byteNum), 2)
			}
			if len(bStr) < 5 {
				padLen := 5 - len(bStr)
				for pIdx := 0; pIdx < padLen; pIdx++ {
					bStr = "0" + bStr
				}
			}

			x += bStr
		}

		eightSize := (len(x) + 7) / 8
		eightBits := make([]string, 0, eightSize)
		for k := 0; k < eightSize; k++ {
			end := 8*k + 8
			if end >= len(x) {
				end = len(x)
			}

			eightBits = append(eightBits, x[8*k:end])
		}

		for z := 0; z < len(eightBits); z++ {
			y := bin2dec(eightBits[z])
			c := byte(y)
			binaries = append(binaries, c)
		}
	}

	return binaries, nil
}

func bin2dec(input string) int {
	num := 0
	base := 1
	for i := len(input) - 1; i >= 0; i-- {
		c := input[i]
		if c >= '0' && c <= '9' {
			num += int(c - '0') * base
		}
		base *= 2
	}

	return num
}

func getByteCountInString(str string, b byte) int {
	cnt := 0
	for i := 0; i < len(str); i++ {
		if b == str[i] {
			cnt++
		}
	}
	return cnt
}

// Get array with all 32 characters for decoding from/encoding to base32.
func getBase32LookupTable() []byte {
	return []byte{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
		'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
		'=', // padding char
	}
}
