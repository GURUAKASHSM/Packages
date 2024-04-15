package typeconversionservice

import (
	"math"
	"strconv"
)

func IntToInt32(n int) int32 {
	if n < math.MinInt32 || n > math.MaxInt32 {
		panic("integer out of range for int32")
	}
	return int32(n)
}

func IntToInt64(n int) int64 {
	return int64(n)
}

func IntToUint(n int) uint {
	if n < 0 {
		panic("negative integer cannot be converted to uint")
	}
	return uint(n)
}

func IntToInt8(n int) int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return int8(n)
}

func IntToInt16(n int) int16 {
	if n < math.MinInt16 || n > math.MaxInt16 {
		panic("integer out of range for int16")
	}
	return int16(n)
}

func IntToUint8(n int) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return uint8(n)
}

func IntToUint16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("integer out of range for uint16")
	}
	return uint16(n)
}

func IntToUint32(n int) uint32 {
	if n < 0 {
		panic("negative integer cannot be converted to uint32")
	}
	return uint32(n)
}

func IntToUint64(n int) uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return uint64(n)
}

func IntToFloat32(n int) float32 {
	return float32(n)
}

func IntToFloat64(n int) float64 {
	return float64(n)
}

func IntToString(n int) string {
	return strconv.Itoa(n)
}

func IntToInterface(n int) interface{} {
	return n
}

func IntToBool(n int)bool{
	if n <= 0{
		return false
	}else{
		return true
	}
}

func IntToArrayofInteger(n int) []int {
	str := strconv.Itoa(n)
	digits := make([]int, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		digits[i] = digit
	}

	return digits
}

func IntToArrayofFloat32(n int) []float32 {
	str := strconv.Itoa(n)
	digits := make([]float32, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		float32digit := IntToFloat32(digit)
		digits[i] = float32digit
	}

	return digits
}

func IntToArrayofFloat64(n int) []float64 {
	str := strconv.Itoa(n)
	digits := make([]float64, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		float64digit := IntToFloat64(digit)
		digits[i] = float64digit
	}

	return digits
}

func IntToArrayofString(n int) []string {
	str := strconv.Itoa(n)
	digits := make([]string, len(str))
	for i, char := range str {
		digit := string(char)		
		digits[i] = digit
	}
	return digits
}

func IntToArrayofInt8(n int) []int8 {
	str := strconv.Itoa(n)
	digits := make([]int8, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		int8digit := IntToInt8(digit)
		digits[i] = int8digit
	}

	return digits
}

func IntToArrayofInt16(n int) []int16 {
	str := strconv.Itoa(n)
	digits := make([]int16, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		int16digit := IntToInt16(digit)
		digits[i] = int16digit
	}

	return digits
}

func IntToArrayofInt32(n int) []int32 {
	str := strconv.Itoa(n)
	digits := make([]int32, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		int32digit := IntToInt32(digit)
		digits[i] = int32digit
	}

	return digits
}

func IntToArrayofInt64(n int) []int64 {
	str := strconv.Itoa(n)
	digits := make([]int64, len(str))
	for i, char := range str {
		digit, err := strconv.Atoi(string(char))
		if err != nil {
			panic(err)
		}
		int64digit := IntToInt64(digit)
		digits[i] = int64digit
	}

	return digits
}


