package remote

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"
)

const encryptedProtocol = "application/HTTP-SPNEGO-session-encrypted"
const maxResponse = 4 * 1024 * 1024

type securitySession interface {
	Wrap([]byte) ([]byte, []byte, error)
	Unwrap([]byte, []byte) ([]byte, error)
}

func sealMessage(session securitySession, plain []byte) ([]byte, string, error) {
	sealed, signature, err := session.Wrap(plain)
	if err != nil {
		return nil, "", errors.New("NTLM message sealing failed")
	}
	if len(signature) != 16 {
		return nil, "", errors.New("NTLM signing was not negotiated")
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "--Encrypted Boundary\r\n\tContent-Type: %s\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n", encryptedProtocol, len(plain))
	body.Write([]byte{16, 0, 0, 0})
	body.Write(signature)
	body.Write(sealed)
	body.WriteString("--Encrypted Boundary--\r\n")
	return body.Bytes(), `multipart/encrypted;protocol="` + encryptedProtocol + `";boundary="Encrypted Boundary"`, nil
}

func unsealMessage(session securitySession, body []byte, contentType string) ([]byte, error) {
	bad := errors.New("invalid encrypted WinRM response")
	typ, params, err := mime.ParseMediaType(contentType)
	boundary := params["boundary"]
	if err != nil || typ != "multipart/encrypted" || params["protocol"] != encryptedProtocol || len(boundary) == 0 || len(boundary) > 70 || strings.ContainsAny(boundary, "\r\n") || len(body) > maxResponse {
		return nil, bad
	}
	marker := []byte("--" + boundary + "\r\n")
	end := []byte("--" + boundary + "--\r\n")
	if !bytes.HasPrefix(body, marker) || !bytes.HasSuffix(body, end) {
		return nil, bad
	}
	body = body[len(marker) : len(body)-len(end)]
	header, payload, ok := bytes.Cut(body, marker)
	if !ok {
		return nil, bad
	}
	length := -1
	protocolOK := false
	for _, line := range strings.Split(string(header), "\r\n") {
		line = strings.TrimSpace(line)
		if line == "Content-Type: "+encryptedProtocol {
			protocolOK = true
		}
		if strings.HasPrefix(line, "OriginalContent:") {
			for _, param := range strings.Split(line, ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && key == "Length" {
					length, err = strconv.Atoi(value)
					if err != nil {
						return nil, bad
					}
				}
			}
		}
	}
	if !protocolOK || length < 0 || length > maxResponse {
		return nil, bad
	}
	line, data, ok := bytes.Cut(payload, []byte("\r\n"))
	if !ok || strings.TrimSpace(string(line)) != "Content-Type: application/octet-stream" || len(data) < 20 {
		return nil, bad
	}
	if binary.LittleEndian.Uint32(data[:4]) != 16 {
		return nil, bad
	}
	plain, err := session.Unwrap(data[20:], data[4:20])
	if err != nil {
		return nil, errors.New("NTLM response signature verification failed")
	}
	if len(plain) != length {
		return nil, bad
	}
	return plain, nil
}
