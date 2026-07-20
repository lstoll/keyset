package keyset

import (
	"encoding/binary"
	"errors"
)

const (
	outputVersion    byte = 1
	outputHeaderSize int  = 5
)

var errInvalidOutput = errors.New("keyset: invalid output framing")

func outputHeader(keyID uint32) [outputHeaderSize]byte {
	var header [outputHeaderSize]byte
	header[0] = outputVersion
	binary.BigEndian.PutUint32(header[1:], keyID)
	return header
}

func parseOutputHeader(in []byte) (uint32, []byte, error) {
	if len(in) < outputHeaderSize || in[0] != outputVersion {
		return 0, nil, errInvalidOutput
	}
	return binary.BigEndian.Uint32(in[1:outputHeaderSize]), in[outputHeaderSize:], nil
}

func framedAAD(domain string, header, aad []byte) []byte {
	out := make([]byte, 0, len(domain)+len(header)+len(aad))
	out = append(out, domain...)
	out = append(out, header...)
	out = append(out, aad...)
	return out
}
