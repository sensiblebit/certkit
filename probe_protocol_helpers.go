package certkit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const maxUint24 = 1<<24 - 1

var (
	errProtocolLengthOverflow = errors.New("protocol length exceeds encoding limit")
	errProtocolValueOverflow  = errors.New("protocol value exceeds encoding limit")
)

func checkedUint8Len(n int, field string) (byte, error) {
	if n < 0 || n > math.MaxUint8 {
		return 0, fmt.Errorf("%w for %s: %d outside range [0, %d]", errProtocolLengthOverflow, field, n, math.MaxUint8)
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(n))
	return buf[1], nil
}

func checkedUint16Len(n int, field string) (uint16, error) {
	if n < 0 || n > math.MaxUint16 {
		return 0, fmt.Errorf("%w for %s: %d outside range [0, %d]", errProtocolLengthOverflow, field, n, math.MaxUint16)
	}
	return uint16(n), nil
}

func checkedUint24Len(n int, field string) (uint32, error) {
	if n < 0 || n > maxUint24 {
		return 0, fmt.Errorf("%w for %s: %d outside range [0, %d]", errProtocolLengthOverflow, field, n, maxUint24)
	}
	return uint32(n), nil
}

func checkedUint32Len(n int, field string) (uint32, error) {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return 0, fmt.Errorf("%w for %s: %d outside range [0, %d]", errProtocolLengthOverflow, field, n, uint64(math.MaxUint32))
	}
	return uint32(n), nil
}

func checkedIntFromUint64(n uint64, field string) (int, error) {
	if n > uint64(math.MaxInt) {
		return 0, fmt.Errorf("%w for %s: %d > %d", errProtocolValueOverflow, field, n, math.MaxInt)
	}
	return int(n), nil
}

func appendUint16(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}

func appendUint24(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[1:]...)
}
