package typeconversionservice

import (
	"math"
	"strconv"
)

func Int16ToInt(n int16) int {
	return int(n)
}

func Int16ToInt8(n int16) int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return int8(n)
}

func Int16ToInt32(n int16) int32 {
	return int32(n)
}

func Int16ToInt64(n int16) int64 {
	return int64(n)
}

func Int16ToUint(n int16) uint {
	if n < 0 {
		panic("negative integer cannot be converted to uint")
	}
	return uint(n)
}

func Int16ToUint8(n int16) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return uint8(n)
}

func Int16ToUint16(n int16) uint16 {
	if n < 0 {
		panic("negative integer cannot be converted to uint16")
	}
	return uint16(n)
}

func Int16ToUint32(n int16) uint32 {
	if n < 0 {
		panic("negative integer cannot be converted to uint32")
	}
	return uint32(n)
}

func Int16ToUint64(n int16) uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return uint64(n)
}

func Int16ToFloat32(n int16) float32 {
	return float32(n)
}

func Int16ToFloat64(n int16) float64 {
	return float64(n)
}

func Int16ToString(n int16) string {
	return strconv.Itoa(int(n))
}

func Int16ToInterface(n int16) interface{} {
	return n
}

func Int16ToBool(n int16) bool {
	return n != 0
}

func Int16ToArrayofInteger(n int16) []int {
	return []int{int(n)}
}

func Int16ToArrayofFloat32(n int16) []float32 {
	return []float32{float32(n)}
}

func Int16ToArrayofFloat64(n int16) []float64 {
	return []float64{float64(n)}
}

func Int16ToArrayofString(n int16) []string {
	return []string{strconv.Itoa(int(n))}
}

func Int16ToArrayofInt8(n int16) []int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return []int8{int8(n)}
}

func Int16ToArrayofInt32(n int16) []int32 {
	return []int32{int32(n)}
}

func Int16ToArrayofInt64(n int16) []int64 {
	return []int64{int64(n)}
}

func Int16ToArrayofUint(n int16) []uint {
	return []uint{uint(n)}
}

func Int16ToArrayofUint8(n int16) []uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return []uint8{uint8(n)}
}

func Int16ToArrayofUint32(n int16) []uint32 {
	return []uint32{uint32(n)}
}

func Int16ToArrayofUint64(n int16) []uint64 {
	return []uint64{uint64(n)}
}

func Int16ToArrayofBool(n int16) []bool {
	return []bool{n != 0}
}
