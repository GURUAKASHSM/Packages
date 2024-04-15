package typeconversionservice

import (
	"strconv"
)

func Int8ToInt(n int8) int {
	return int(n)
}

func Int8ToInt32(n int8) int32 {
	return int32(n)
}

func Int8ToInt64(n int8) int64 {
	return int64(n)
}

func Int8ToUint(n int8) uint {
	if n < 0 {
		panic("negative integer cannot be converted to uint")
	}
	return uint(n)
}

func Int8ToUint8(n int8) uint8 {
	if n < 0 {
		panic("negative integer cannot be converted to uint8")
	}
	return uint8(n)
}

func Int8ToUint16(n int8) uint16 {
	if n < 0 {
		panic("negative integer cannot be converted to uint16")
	}
	return uint16(n)
}

func Int8ToUint32(n int8) uint32 {
	if n < 0 {
		panic("negative integer cannot be converted to uint32")
	}
	return uint32(n)
}

func Int8ToUint64(n int8) uint64 {
	if n < 0 {
		panic("negative integer cannot be converted to uint64")
	}
	return uint64(n)
}

func Int8ToFloat32(n int8) float32 {
	return float32(n)
}

func Int8ToFloat64(n int8) float64 {
	return float64(n)
}

func Int8ToString(n int8) string {
	return strconv.Itoa(int(n))
}

func Int8ToInterface(n int8) interface{} {
	return n
}

func Int8ToBool(n int8) bool {
	return n != 0
}

func Int8ToArrayofInteger(n int8) []int {
	return []int{int(n)}
}

func Int8ToArrayofFloat32(n int8) []float32 {
	return []float32{float32(n)}
}

func Int8ToArrayofFloat64(n int8) []float64 {
	return []float64{float64(n)}
}

func Int8ToArrayofString(n int8) []string {
	return []string{strconv.Itoa(int(n))}
}

func Int8ToArrayofInt16(n int8) []int16 {
	return []int16{int16(n)}
}

func Int8ToArrayofInt32(n int8) []int32 {
	return []int32{int32(n)}
}

func Int8ToArrayofInt64(n int8) []int64 {
	return []int64{int64(n)}
}

func Int8ToArrayofUint(n int8) []uint {
	return []uint{uint(n)}
}

func Int8ToArrayofUint8(n int8) []uint8 {
	return []uint8{uint8(n)}
}

func Int8ToArrayofUint16(n int8) []uint16 {
	return []uint16{uint16(n)}
}

func Int8ToArrayofUint32(n int8) []uint32 {
	return []uint32{uint32(n)}
}

func Int8ToArrayofUint64(n int8) []uint64 {
	return []uint64{uint64(n)}
}

func Int8ToArrayofBool(n int8) []bool {
	return []bool{n != 0}
}
