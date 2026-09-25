package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type receiveResult struct {
	code int
	err  error
}
type copyResult struct {
	bytes int64
	err   error
}

type transferProgressWriter struct {
	to       io.Writer
	count    int64
	progress func(int64)
}

func (w *transferProgressWriter) Write(p []byte) (int, error) {
	n, err := w.to.Write(p)
	w.count += int64(n)
	if n > 0 && w.progress != nil {
		w.progress(w.count)
	}
	return n, err
}

func download(ctx context.Context, req TransferRequest, progress func(int64), p poster) (TransferResult, error) {
	return downloadLanes(ctx, req, progress, p, sharedLanes(p))
}

func downloadLanes(ctx context.Context, req TransferRequest, progress func(int64), p poster, lanes dataLanes) (result TransferResult, runErr error) {
	if req.Direction != Download {
		return result, &TransferInputError{Message: "invalid transfer direction"}
	}
	if req.LocalPath == "" {
		return result, &TransferInputError{Message: "local path is empty"}
	}
	if err := validateRemotePath(req.RemotePath); err != nil {
		return result, &TransferInputError{Message: err.Error()}
	}
	destination, err := filepath.Abs(req.LocalPath)
	if err != nil {
		return result, fmt.Errorf("local destination: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return result, fmt.Errorf("local destination parent: %w", err)
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	if err := rejectLocalLink(destination); err != nil {
		return result, err
	}
	transferID, err := randomTransferID()
	if err != nil {
		return result, err
	}
	tempScript, err := transferScript("temp.ps1", nil)
	if err != nil {
		return result, err
	}
	lane, closeLanes, err := lanes(ctx)
	if err != nil {
		return result, fmt.Errorf("authenticate data connections: %w", err)
	}
	// Deferred first, so it runs after every session and cleanup.
	defer closeLanes()
	tempOut, rc, err := transferControl(ctx, req.Connection, tempScript, p, lane.cleanup)
	if err != nil {
		return result, fmt.Errorf("remote temp: %w", err)
	}
	if rc != 0 {
		return result, &RemoteExitError{Code: rc}
	}
	tempDir := strings.TrimSpace(tempOut)
	metadata := strings.TrimRight(tempDir, `\/`) + `\winsh-result-` + transferID + `.json`
	if err := validateRemotePath(metadata); err != nil {
		return result, errors.New("invalid remote temporary directory")
	}

	stage, err := createStage(destination)
	if err != nil {
		return result, fmt.Errorf("local stage: %w", err)
	}
	stageName := stage.Name()
	defer func() { _ = stage.Close(); _ = os.Remove(stageName) }()

	script, err := transferScript("download.ps1", map[string]string{"id": transferID, "source": req.RemotePath, "metadata": metadata})
	if err != nil {
		return result, err
	}
	s, err := startSessionLanes(ctx, Request{Endpoint: req.Connection.Endpoint, TargetHost: req.Connection.TargetHost, User: req.Connection.User, Password: req.Connection.Password, Command: script, PowerShell: true}, p, lane.cleanup, lane.send, lane.receive, p)
	if err != nil {
		return result, fmt.Errorf("start sender: %w", err)
	}
	senderDone := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.close(cleanup); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close sender: %w", err))
			result.Artifacts = append(result.Artifacts, metadata)
			return
		}
		if !senderDone {
			result.Artifacts = append(result.Artifacts, metadata)
			return
		}
		// The control record gets its own budget after the sender's Delete.
		recordCtx, cancelRecord := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelRecord()
		if err := cleanupRemoteStage(recordCtx, req, metadata, lane.cleanup, p); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("remove control record: %w", err))
			result.Artifacts = append(result.Artifacts, metadata)
		}
	}()

	reader, writer := io.Pipe()
	stderr := boundedOutput{limit: 1024}
	recvCh := make(chan receiveResult, 1)
	copyCh := make(chan copyResult, 1)
	go func() {
		rc, err := s.receive(ctx, writer, &stderr)
		_ = writer.CloseWithError(err)
		recvCh <- receiveResult{rc, err}
	}()
	go func() {
		n, err := copyBase64Lines(&transferProgressWriter{to: stage, progress: progress}, reader, 32768)
		_ = reader.CloseWithError(err)
		copyCh <- copyResult{n, err}
	}()
	sendErr := s.send(ctx, nil, true)
	if sendErr != nil {
		_ = s.close(ctx)
	}
	copyDone := <-copyCh
	if copyDone.err != nil {
		_ = s.close(ctx)
	}
	received := <-recvCh
	if sendErr != nil {
		return result, fmt.Errorf("send sender EOF: %w", sendErr)
	}
	if copyDone.err != nil {
		return result, fmt.Errorf("decode download: %w", copyDone.err)
	}
	if received.err != nil {
		return result, fmt.Errorf("receive download: %w", received.err)
	}
	if received.code != 0 {
		return result, &RemoteExitError{Code: received.code}
	}
	if stderr.Len() != 0 {
		return result, errors.New("sender reported an error")
	}
	senderDone = true
	fetchScript, err := transferScript("fetch.ps1", map[string]string{"metadata": metadata})
	if err != nil {
		return result, err
	}
	control, rc, err := transferControl(ctx, req.Connection, fetchScript, p, lane.cleanup)
	if err != nil {
		return result, fmt.Errorf("fetch control record: %w", err)
	}
	if rc != 0 {
		return result, &RemoteExitError{Code: rc}
	}
	record, err := readRecord(strings.NewReader(control), transferID)
	if err != nil {
		return result, fmt.Errorf("control record: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return result, fmt.Errorf("sync stage: %w", err)
	}
	count, sum, err := hashStage(stage)
	if err != nil {
		return result, err
	}
	if count != copyDone.bytes || count != record.Bytes || sum != record.SHA256 {
		return result, errors.New("download integrity mismatch")
	}
	if err := stage.Close(); err != nil {
		return result, fmt.Errorf("close stage: %w", err)
	}
	if err := commitStage(stageName, destination, req.Force); err != nil {
		return result, fmt.Errorf("commit download: %w", err)
	}
	return TransferResult{Bytes: count, SHA256: sum, Committed: true}, nil
}

func rejectLocalLink(path string) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return &TransferInputError{Message: "local destination is a symlink"}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect local destination: %w", err)
	}
	return nil
}

func transferControl(ctx context.Context, connection Request, script string, p, cleanup poster) (string, int, error) {
	request := connection
	request.Command = script
	request.PowerShell = true
	stdout, stderr := boundedOutput{limit: transferRecordMaxSize}, boundedOutput{limit: 1024}
	rc, err := runWithCleanup(ctx, request, &stdout, &stderr, p, cleanup, p)
	if err != nil {
		return "", 0, err
	}
	if stderr.Len() != 0 {
		return "", 0, errors.New("remote control command reported an error")
	}
	return stdout.String(), rc, nil
}
