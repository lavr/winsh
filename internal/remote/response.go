package remote

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const wsShell = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/"
const wsTransfer = "http://schemas.xmlsoap.org/ws/2004/09/transfer/"

var errOperationTimeout = errors.New("WinRM operation timeout")

type response struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
	Header  struct {
		Action string `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing Action"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
	Body struct {
		Fault *struct {
			Detail struct {
				Fault struct {
					Code string `xml:"Code,attr"`
				} `xml:"http://schemas.microsoft.com/wbem/wsman/1/wsmanfault WSManFault"`
			} `xml:"http://www.w3.org/2003/05/soap-envelope Detail"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`
		Shell struct {
			ID string `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell ShellId"`
		} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell Shell"`
		Command struct {
			ID string `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell CommandId"`
		} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell CommandResponse"`
		Receive *struct {
			Streams []struct {
				Name string `xml:"Name,attr"`
				Data string `xml:",chardata"`
			} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell Stream"`
			State struct {
				Value string `xml:"State,attr"`
				Exit  string `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell ExitCode"`
			} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell CommandState"`
		} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell ReceiveResponse"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
}

func parseResponse(body string) (response, error) {
	var r response
	if err := xml.Unmarshal([]byte(body), &r); err != nil {
		return r, errors.New("invalid SOAP XML response")
	}
	if r.Body.Fault != nil {
		code := r.Body.Fault.Detail.Fault.Code
		if code == "2150858793" {
			return r, errOperationTimeout
		}
		if n, err := strconv.ParseUint(code, 10, 32); err == nil {
			return r, fmt.Errorf("WinRM fault %d", n)
		}
		return r, errors.New("WinRM SOAP fault")
	}
	return r, nil
}

func (r response) receive(stdout, stderr io.Writer) (bool, int, error) {
	if r.Header.Action != wsShell+"ReceiveResponse" || r.Body.Receive == nil {
		return false, 0, errors.New("expected WinRM ReceiveResponse")
	}
	output := r.Body.Receive
	for _, stream := range output.Streams {
		data, err := base64.StdEncoding.DecodeString(stream.Data)
		if err != nil {
			return false, 0, errors.New("invalid base64 output from WinRM")
		}
		var w io.Writer
		switch stream.Name {
		case "stdout":
			w = stdout
		case "stderr":
			w = stderr
		default:
			return false, 0, errors.New("unexpected WinRM stream")
		}
		n, err := w.Write(data)
		if err != nil {
			return false, 0, fmt.Errorf("writing command output: %w", err)
		}
		if n != len(data) {
			return false, 0, io.ErrShortWrite
		}
	}
	if output.State.Value == wsShell+"CommandState/Done" {
		code, err := strconv.ParseUint(strings.TrimSpace(output.State.Exit), 10, 32)
		if err != nil {
			return false, 0, errors.New("invalid or missing remote exit code")
		}
		return true, int(code), nil
	}
	return false, 0, nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
