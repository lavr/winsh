package remote

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTransferRejectsUnknownDirectionBeforeNetwork(t *testing.T) {
	_, err := Transfer(t.Context(), TransferRequest{Direction: "fetch", RemotePath: `C:\Temp\source`, LocalPath: "local"}, nil)
	if !IsTransferInputError(err) {
		t.Fatalf("error=%v", err)
	}
}

func TestTransferDispatchesUpload(t *testing.T) {
	req, _, payload, sum := uploadFixture(t)
	f := &uploadFake{receiverStdout: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":%d,"sha256":"%s"}`, len(payload), sum), finalizerStdout: "OK: committed"}
	r, err := transfer(t.Context(), req, nil, postFunc(f.post))
	if err != nil || !r.Committed || r.Bytes != int64(len(payload)) {
		t.Fatalf("result=%+v err=%v", r, err)
	}
}

func TestTransferDispatchesDownload(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "empty")
	f := &downloadFake{record: `{"version":1,"id":"placeholder","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`}
	r, err := transfer(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err != nil || !r.Committed {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	}
}

func TestTransferInvalidRemotePathBeforeNetwork(t *testing.T) {
	_, err := transfer(context.Background(), TransferRequest{Direction: Download, RemotePath: `C:relative`, LocalPath: "file"}, nil, postFunc(func(context.Context, string) (string, error) { t.Error("network called"); return "", nil }))
	if !IsTransferInputError(err) {
		t.Fatalf("error=%v", err)
	}
}
