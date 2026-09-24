package remote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	winrm "github.com/masterzen/winrm"
)

// uploadChunkRaw is the maximum raw bytes packed into a single Base64
// line sent through WinRM SendInput. The plan keeps it conservative
// against the WSMan envelope bound and the SOAP Base64 expansion on the
// receiver side.
const uploadChunkRaw = 32 * 1024

// upload sends the local file at TransferRequest.LocalPath to the
// remote path at TransferRequest.RemotePath through the existing
// WinRM endpoint.
//
// State machine:
//
//	streaming       -> raw bytes are read and sent via SendInput
//	stage_verified  -> receiver's control record agrees with our hash+count
//	commit_dispatched -> finalizer command has been sent to the server
//	commit_confirmed   -> finalizer reported the destination committed
//
// Errors before commit_dispatched preserve the destination (or its
// absence). Errors after commit_dispatched but before commit_confirmed
// return *FinalizationUnknownError so the caller knows the destination
// may contain either the previous file or the new one. errors.Is keeps
// working because Cause is preserved on the wrapper.
func upload(ctx context.Context, req TransferRequest, progress func(int64), p poster) (TransferResult, error) {
	return uploadLanes(ctx, req, progress, p, sharedLanes(p))
}

func uploadLanes(ctx context.Context, req TransferRequest, progress func(int64), p poster, lanes dataLanes) (result TransferResult, runErr error) {
	if req.Direction != Upload {
		return TransferResult{}, fmt.Errorf("upload: wrong direction %q", req.Direction)
	}
	if req.LocalPath == "" || req.RemotePath == "" {
		return TransferResult{}, &TransferInputError{Message: "local and remote paths must not be empty"}
	}
	if err := validateRemotePath(req.RemotePath); err != nil {
		return TransferResult{}, &TransferInputError{Message: err.Error()}
	}

	// Open the local source. The handle is the upload's only handle on
	// the source bytes; a concurrent local rename after this point would
	// not be observed until we re-stat at the end of streaming.
	src, info, err := openSource(req.LocalPath)
	if err != nil {
		return TransferResult{}, fmt.Errorf("open source: %w", err)
	}
	defer src.Close()
	initialSize := info.Size()

	transferID, err := randomTransferID()
	if err != nil {
		return TransferResult{}, fmt.Errorf("transfer id: %w", err)
	}
	stageParent, err := remoteStageParent(req.RemotePath)
	if err != nil {
		return TransferResult{}, &TransferInputError{Message: err.Error()}
	}
	stagePath := strings.TrimRight(stageParent, `\/`) + `\.winsh-stage-` + transferID

	receiverCmd, err := transferScript("upload.ps1", map[string]string{
		"id":    transferID,
		"stage": stagePath,
	})
	if err != nil {
		return TransferResult{}, fmt.Errorf("build receiver script: %w", err)
	}

	sendLane, recvLane, closeLanes, err := lanes(ctx)
	if err != nil {
		return TransferResult{}, fmt.Errorf("authenticate data connections: %w", err)
	}
	// Deferred first, so it runs after the receiver session is closed.
	defer closeLanes()
	sess, err := startSessionLanes(ctx, Request{
		Endpoint:   req.Connection.Endpoint,
		TargetHost: req.Connection.TargetHost,
		User:       req.Connection.User,
		Password:   req.Connection.Password,
		Command:    receiverCmd,
		PowerShell: true,
	}, p, p, sendLane, recvLane)
	if err != nil {
		return TransferResult{}, fmt.Errorf("start receiver: %w", err)
	}
	chunkLimit, err := chunkSize(153600, func(data []byte) (string, error) {
		line := make([]byte, base64.StdEncoding.EncodedLen(len(data))+2)
		base64.StdEncoding.Encode(line, data)
		line[len(line)-2], line[len(line)-1] = '\r', '\n'
		msg := winrm.NewSendInputRequest(sess.endpoint, sess.shellID, sess.commandID, line, false, sess.params)
		defer msg.Free()
		return msg.String(), nil
	})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = sess.close(cleanupCtx)
		cancel()
		return TransferResult{}, fmt.Errorf("size transfer chunk: %w", err)
	}
	if chunkLimit > uploadChunkRaw {
		chunkLimit = uploadChunkRaw
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := sess.close(cleanupCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close receiver: %w", err))
			if runErr != nil && !result.Committed {
				result.Artifacts = append(result.Artifacts, stagePath)
			}
			return
		}
		var unknown *FinalizationUnknownError
		if runErr != nil && !result.Committed {
			result.Artifacts = append(result.Artifacts, stagePath)
			if !errors.As(runErr, &unknown) {
				if err := cleanupRemoteStage(cleanupCtx, req, stagePath, p); err == nil {
					result.Artifacts = nil
				} else {
					runErr = errors.Join(runErr, fmt.Errorf("remove remote stage: %w", err))
				}
			}
		}
	}()

	// Start output polling before streaming. WinRM's Receive protocol
	// recommends issuing Receive immediately, even while Send is active,
	// to avoid deadlock or timeout. The session owns and cancels this
	// worker on every return path.
	stdout, stderr := boundedOutput{limit: transferRecordMaxSize}, boundedOutput{limit: 1024}
	// The receiver exits only after EOF. If it exits earlier, stop
	// streaming: cancel an in-flight Send and send nothing more.
	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()
	received := make(chan receiveResult, 1)
	go func() {
		rc, err := sess.receive(ctx, &stdout, &stderr)
		received <- receiveResult{code: rc, err: err}
		stopStream()
	}()
	earlyExit := func(sendErr error) error {
		if ctx.Err() != nil || streamCtx.Err() == nil {
			return sendErr
		}
		recv := <-received
		received <- recv
		if recv.err != nil {
			return fmt.Errorf("receiver stopped before end of input: %w", recv.err)
		}
		return fmt.Errorf("receiver exited before end of input with code %d", recv.code)
	}

	sha := sha256.New()
	totalSent := int64(0)
	chunk := make([]byte, chunkLimit)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(chunkLimit)+2)

	for {
		if err := streamCtx.Err(); err != nil {
			return TransferResult{}, fmt.Errorf("send chunk: %w", earlyExit(err))
		}
		n, rerr := src.Read(chunk)
		if n > 0 {
			sha.Write(chunk[:n])
			base64.StdEncoding.Encode(encoded, chunk[:n])
			line := append(encoded[:base64.StdEncoding.EncodedLen(n)], '\r', '\n')
			if err := sess.send(streamCtx, line, false); err != nil {
				return TransferResult{}, fmt.Errorf("send chunk: %w", earlyExit(err))
			}
			totalSent += int64(n)
			if progress != nil {
				progress(totalSent)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return TransferResult{}, fmt.Errorf("read source: %w", rerr)
		}
	}

	if err := sess.send(streamCtx, nil, true); err != nil {
		return TransferResult{}, fmt.Errorf("send eof: %w", earlyExit(err))
	}

	// Stage was written and the receiver is computing SHA-256. Drain
	// receive until the command exits; the control record is the only
	// thing on stdout.
	recv := <-received
	if recv.err != nil {
		return TransferResult{}, fmt.Errorf("receive result: %w", recv.err)
	}
	if recv.code != 0 {
		return TransferResult{}, &RemoteExitError{Code: recv.code}
	}
	if stderr.Len() > 0 {
		return TransferResult{}, errors.New("receiver reported an error")
	}

	// Source stat-change check: if the source was replaced locally
	// between openSource and now, the streamed bytes may not represent
	// the current file. The receiver's hash covers what was sent; we
	// reject if the local file grew beyond what we sent.
	cur, statErr := src.Stat()
	pathInfo, pathErr := os.Stat(req.LocalPath)
	if statErr != nil || pathErr != nil || !os.SameFile(info, pathInfo) || cur.Size() != initialSize || !cur.ModTime().Equal(info.ModTime()) || totalSent != initialSize {
		return TransferResult{}, errors.New("source changed during transfer")
	}

	localSHA := hex.EncodeToString(sha.Sum(nil))
	rec, err := readRecord(&stdout, transferID)
	if err != nil {
		return TransferResult{}, fmt.Errorf("stage result: %w", err)
	}
	if rec.Bytes != totalSent {
		return TransferResult{}, fmt.Errorf("stage count mismatch: sent=%d reported=%d", totalSent, rec.Bytes)
	}
	if rec.SHA256 != localSHA {
		return TransferResult{}, errors.New("stage hash mismatch")
	}

	// Stage verified; the receiver shell can be torn down. We keep
	// the stage on disk for the finalizer to consume.
	commitCleanupCtx, commitCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	if err := sess.close(commitCleanupCtx); err != nil {
		commitCancel()
		return TransferResult{Bytes: totalSent, SHA256: localSHA},
			fmt.Errorf("close receiver before commit: %w", err)
	}
	commitCancel()

	return dispatchFinalizer(ctx, req, transferID, stagePath, localSHA, totalSent, p)
}

// dispatchFinalizer runs the control.ps1 command that re-verifies the
// stage and applies the atomic commit. It is the second of the two
// WinRM sessions an upload creates. The result is Committed=true only
// when the finalizer reports OK; otherwise FinalizationUnknownError
// signals that the destination may now contain either the previous or
// the new bytes.
//
// The cleanup context supplied to the second session is independent
// from the receiver session's budget. A new five-second slice is used
// here so the finalizer cannot eat into the cleanup that the caller
// allocated for the receiver.
func dispatchFinalizer(ctx context.Context, req TransferRequest, transferID, stagePath, sha256Hex string, byteCount int64, p poster) (result TransferResult, runErr error) {
	force := "false"
	if req.Force {
		force = "true"
	}
	finalizerCmd, err := transferScript("control.ps1", map[string]string{
		"id":              transferID,
		"stage":           stagePath,
		"destination":     req.RemotePath,
		"expected_sha256": sha256Hex,
		"expected_bytes":  fmt.Sprint(byteCount),
		"force":           force,
	})
	if err != nil {
		return TransferResult{Bytes: byteCount, SHA256: sha256Hex}, fmt.Errorf("build finalizer: %w", err)
	}

	sess, err := startSession(ctx, Request{
		Endpoint:   req.Connection.Endpoint,
		TargetHost: req.Connection.TargetHost,
		User:       req.Connection.User,
		Password:   req.Connection.Password,
		Command:    finalizerCmd,
		PowerShell: true,
	}, p)
	if err != nil {
		return TransferResult{Bytes: byteCount, SHA256: sha256Hex},
			&FinalizationUnknownError{Cause: fmt.Errorf("start finalizer: %w", err)}
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := sess.close(cleanupCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close finalizer: %w", err))
		}
	}()

	if err := sess.send(ctx, nil, true); err != nil {
		return TransferResult{Bytes: byteCount, SHA256: sha256Hex},
			&FinalizationUnknownError{Cause: fmt.Errorf("send finalizer eof: %w", err)}
	}

	stdout, stderr := boundedOutput{limit: 256}, boundedOutput{limit: 1024}
	rc, err := sess.receive(ctx, &stdout, &stderr)
	if err != nil {
		return TransferResult{Bytes: byteCount, SHA256: sha256Hex},
			&FinalizationUnknownError{Cause: fmt.Errorf("receive finalizer: %w", err)}
	}
	if rc != 0 {
		// Non-zero rc means the finalizer rejected the commit (stage
		// missing or hash mismatch or MoveFileExW failure). The commit
		// was not issued, so the destination is preserved. Report
		// without FinalizationUnknownError because the previous bytes
		// (or absence) is the known state.
		return TransferResult{Bytes: byteCount, SHA256: sha256Hex},
			&RemoteExitError{Code: rc}
	}
	if strings.TrimSpace(stdout.String()) != "OK: committed:"+transferID || stderr.Len() != 0 {
		return TransferResult{Bytes: byteCount, SHA256: sha256Hex},
			&FinalizationUnknownError{Cause: errors.New("finalizer ack missing")}
	}
	return TransferResult{Bytes: byteCount, SHA256: sha256Hex, Committed: true}, nil
}

func cleanupRemoteStage(ctx context.Context, req TransferRequest, stagePath string, p poster) error {
	script, err := transferScript("cleanup.ps1", map[string]string{"stage": stagePath})
	if err != nil {
		return err
	}
	s, err := startSession(ctx, Request{Endpoint: req.Connection.Endpoint, TargetHost: req.Connection.TargetHost,
		User: req.Connection.User, Password: req.Connection.Password, Command: script, PowerShell: true}, p)
	if err != nil {
		return err
	}
	defer s.close(ctx)
	if err := s.send(ctx, nil, true); err != nil {
		return err
	}
	stdout, stderr := boundedOutput{limit: 256}, boundedOutput{limit: 256}
	rc, err := s.receive(ctx, &stdout, &stderr)
	if err != nil {
		return err
	}
	if rc != 0 || stderr.Len() != 0 || strings.TrimSpace(stdout.String()) != "OK: cleaned" {
		return errors.New("remote stage cleanup failed")
	}
	return nil
}

// randomTransferID returns a 16-byte hex string used to correlate the
// receiver's control record with this upload.
func randomTransferID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
