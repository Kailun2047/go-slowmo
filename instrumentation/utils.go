package instrumentation

import (
	"encoding/binary"
	"math"
	"unsafe"
)

func determineByteOrder() binary.ByteOrder {
	num := math.MaxUint8 + 1
	firstByte := *(*uint8)(unsafe.Pointer(&num))
	if firstByte == 1 {
		return binary.BigEndian
	} else {
		return binary.LittleEndian
	}
}
