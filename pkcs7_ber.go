package certkit

import "fmt"

const maxPKCS7BERDepth = 32

type pkcs7BERObject struct {
	tag        []byte
	content    []byte
	end        int
	indefinite bool
}

// normalizePKCS7BER walks each input byte once and bounds the nesting depth.
// It checks child boundaries and converts all lengths before the recursive
// upstream parser runs. Copying content takes at most maxPKCS7BERDepth passes.
func normalizePKCS7BER(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x30 {
		return nil, errPKCS7ContentInfo
	}
	outer, offset, err := readPKCS7BERHeader(data)
	if err != nil {
		return nil, err
	}
	stack := []pkcs7BERObject{outer}
	for len(stack) > 0 {
		parent := &stack[len(stack)-1]
		complete := !parent.indefinite && offset == parent.end
		if parent.indefinite && parent.end-offset >= 2 && data[offset] == 0 && data[offset+1] == 0 {
			offset += 2
			complete = true
		}
		if complete {
			object := *parent
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				if offset != len(data) {
					return nil, fmt.Errorf("%w: trailing BER data", errPKCS7ContentInfo)
				}
				return appendPKCS7DERObject(nil, object), nil
			}
			parent = &stack[len(stack)-1]
			parent.content = appendPKCS7DERObject(parent.content, object)
			continue
		}
		if offset >= parent.end {
			return nil, fmt.Errorf("%w: missing BER end marker", errPKCS7ContentInfo)
		}
		child, headerLen, err := readPKCS7BERHeader(data[offset:parent.end])
		if err != nil {
			return nil, err
		}
		child.end += offset
		offset += headerLen
		if child.tag[0]&0x20 != 0 {
			if len(stack) >= maxPKCS7BERDepth {
				return nil, fmt.Errorf("%w: BER nesting exceeds %d", errPKCS7ContentInfo, maxPKCS7BERDepth)
			}
			stack = append(stack, child)
		} else {
			child.content = data[offset:child.end]
			parent.content = appendPKCS7DERObject(parent.content, child)
			offset = child.end
		}
	}
	return nil, errPKCS7ContentInfo
}

// readPKCS7BERHeader limits every value to the bytes available in its parent.
func readPKCS7BERHeader(data []byte) (pkcs7BERObject, int, error) {
	var object pkcs7BERObject
	if len(data) < 2 || data[0]&0xdf == 0 {
		return object, 0, fmt.Errorf("%w: invalid BER tag", errPKCS7ContentInfo)
	}
	offset := 1
	if data[0]&0x1f == 0x1f {
		for {
			if offset >= len(data) {
				return object, 0, fmt.Errorf("%w: truncated BER tag", errPKCS7ContentInfo)
			}
			b := data[offset]
			offset++
			if b&0x80 == 0 {
				break
			}
		}
	}
	object.tag = data[:offset]
	if offset >= len(data) {
		return object, 0, fmt.Errorf("%w: missing BER length", errPKCS7ContentInfo)
	}
	first := data[offset]
	offset++
	if first == 0x80 {
		if data[0]&0x20 == 0 {
			return object, 0, fmt.Errorf("%w: indefinite primitive BER value", errPKCS7ContentInfo)
		}
		object.indefinite, object.end = true, len(data)
		return object, offset, nil
	}
	length := int(first)
	if first > 0x80 {
		count := int(first & 0x7f)
		if first == 0xff || count > len(data)-offset {
			return object, 0, fmt.Errorf("%w: invalid BER length", errPKCS7ContentInfo)
		}
		length = 0
		for _, b := range data[offset : offset+count] {
			if length > len(data)/256 || length*256 > len(data)-int(b) {
				return object, 0, fmt.Errorf("%w: BER length exceeds input", errPKCS7ContentInfo)
			}
			length = length*256 + int(b)
		}
		offset += count
	}
	if length > len(data)-offset {
		return object, 0, fmt.Errorf("%w: BER value exceeds parent", errPKCS7ContentInfo)
	}
	object.end = offset + length
	return object, offset, nil
}

func appendPKCS7DERObject(dst []byte, object pkcs7BERObject) []byte {
	dst = append(dst, object.tag...)
	length := len(object.content)
	if length < 128 {
		dst = append(dst, byte(length))
	} else {
		var encoded [8]byte
		start := len(encoded)
		for length > 0 {
			start--
			encoded[start] = byte(length & 0xff)
			length >>= 8
		}
		dst = append(dst, 0x80|byte(len(encoded)-start))
		dst = append(dst, encoded[start:]...)
	}
	return append(dst, object.content...)
}
