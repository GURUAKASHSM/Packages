package typeconversionservice

import (
	"math"
	"strconv"
)

func Int32ToInt(n int32) int {
	return int(n)
}

func Int32ToInt8(n int32) int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return int8(n)
}

func Int32ToInt16(n int32) int16 {
	if n < math.MinInt16 || n > math.MaxInt16 {
		panic("integer out of range for int16")
	}
	return int16(n)
}

func Int32ToInt64(n int32) int64 {
	return int64(n)
}

func Int32ToUint(n int32) uint {
	if n < 0 {
		panic("negative integer cannot be converted to uint")
	}
	return uint(n)
}

func Int32ToUint8(n int32) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return uint8(n)
}

func Int32ToUint16(n int32) uint16 {
	if n < 0 {
		panic("negative integer cannot be converted to uint16")
	}
	return uint16(n)
}

func Int32ToUint32(n int32) uint32 {
	if n < 0 {
		panic("negative integer cannot be converted to uint32")
	}
	return uint32(n)
}

func Int32ToUint64(n int32) uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return uint64(n)
}

func Int32ToFloat32(n int32) float32 {
	return float32(n)
}

func Int32ToFloat64(n int32) float64 {
	return float64(n)
}

func Int32ToString(n int32) string {
	return strconv.Itoa(int(n))
}

func Int32ToInterface(n int32) interface{} {
	return n
}

func Int32ToBool(n int32) bool {
	return n != 0
}

func Int32ToArrayofInteger(n int32) []int {
	return []int{int(n)}
}

func Int32ToArrayofFloat32(n int32) []float32 {
	return []float32{float32(n)}
}

func Int32ToArrayofFloat64(n int32) []float64 {
	return []float64{float64(n)}
}

func Int32ToArrayofString(n int32) []string {
	return []string{strconv.Itoa(int(n))}
}

func Int32ToArrayofInt8(n int32) []int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return []int8{int8(n)}
}

func Int32ToArrayofInt16(n int32) []int16 {
	if n < math.MinInt16 || n > math.MaxInt16 {
		panic("integer out of range for int16")
	}
	return []int16{int16(n)}
}

func Int32ToArrayofInt64(n int32) []int64 {
	return []int64{int64(n)}
}

func Int32ToArrayofUint(n int32) []uint {
	return []uint{uint(n)}
}

func Int32ToArrayofUint8(n int32) []uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return []uint8{uint8(n)}
}

func Int32ToArrayofUint16(n int32) []uint16 {
	if n < 0 {
		panic("negative integer cannot be converted to uint16")
	}
	return []uint16{uint16(n)}
}

func Int32ToArrayofUint64(n int32) []uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return []uint64{uint64(n)}
}

func Int32ToArrayofBool(n int32) []bool {
	return []bool{n != 0}
}
