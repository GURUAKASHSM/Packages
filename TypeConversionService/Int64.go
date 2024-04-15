package typeconversionservice

import (
	"math"
	"strconv"
)

func Int64ToInt(n int64) int {
	if n < math.MinInt32 || n > math.MaxInt32 {
		panic("integer out of range for int")
	}
	return int(n)
}

func Int64ToInt8(n int64) int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return int8(n)
}

func Int64ToInt16(n int64) int16 {
	if n < math.MinInt16 || n > math.MaxInt16 {
		panic("integer out of range for int16")
	}
	return int16(n)
}

func Int64ToInt32(n int64) int32 {
	if n < math.MinInt32 || n > math.MaxInt32 {
		panic("integer out of range for int32")
	}
	return int32(n)
}

func Int64ToUint(n int64) uint {
	if n < 0 {
		panic("negative integer cannot be converted to uint")
	}
	return uint(n)
}

func Int64ToUint8(n int64) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return uint8(n)
}

func Int64ToUint16(n int64) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("integer out of range for uint16")
	}
	return uint16(n)
}

func Int64ToUint32(n int64) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("integer out of range for uint32")
	}
	return uint32(n)
}

func Int64ToUint64(n int64) uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return uint64(n)
}

func Int64ToFloat32(n int64) float32 {
	return float32(n)
}

func Int64ToFloat64(n int64) float64 {
	return float64(n)
}

func Int64ToString(n int64) string {
	return strconv.FormatInt(n, 10)
}

func Int64ToInterface(n int64) interface{} {
	return n
}

func Int64ToBool(n int64) bool {
	return n != 0
}

func Int64ToArrayofInteger(n int64) []int {
	return []int{int(n)}
}

func Int64ToArrayofFloat32(n int64) []float32 {
	return []float32{float32(n)}
}

func Int64ToArrayofFloat64(n int64) []float64 {
	return []float64{float64(n)}
}

func Int64ToArrayofString(n int64) []string {
	return []string{strconv.FormatInt(n, 10)}
}

func Int64ToArrayofInt8(n int64) []int8 {
	if n < math.MinInt8 || n > math.MaxInt8 {
		panic("integer out of range for int8")
	}
	return []int8{int8(n)}
}

func Int64ToArrayofInt16(n int64) []int16 {
	if n < math.MinInt16 || n > math.MaxInt16 {
		panic("integer out of range for int16")
	}
	return []int16{int16(n)}
}

func Int64ToArrayofInt32(n int64) []int32 {
	if n < math.MinInt32 || n > math.MaxInt32 {
		panic("integer out of range for int32")
	}
	return []int32{int32(n)}
}

func Int64ToArrayofUint(n int64) []uint {
	if n < 0 {
		panic("negative integer cannot be converted to uint")
	}
	return []uint{uint(n)}
}

func Int64ToArrayofUint8(n int64) []uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic("integer out of range for uint8")
	}
	return []uint8{uint8(n)}
}

func Int64ToArrayofUint16(n int64) []uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("integer out of range for uint16")
	}
	return []uint16{uint16(n)}
}

func Int64ToArrayofUint32(n int64) []uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("integer out of range for uint32")
	}
	return []uint32{uint32(n)}
}

func Int64ToArrayofUint64(n int64) []uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return []uint64{uint64(n)}
}

func Int64ToArrayofBool(n int64) []bool {
	return []bool{n != 0}
}
