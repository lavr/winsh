package remote

import (
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxCABundleBytes = 8 * 1024 * 1024
const maxCADirEntries = 4096

// configuredRootPool uses explicit Unix CA settings as the trust root set.
// Go's macOS verifier does not read SSL_CERT_FILE or SSL_CERT_DIR itself, and
// Go may cache SystemCertPool across calls on Linux. A configured but
// unreadable/invalid source fails closed before any request.
func configuredRootPool() (*x509.CertPool, error) {
	file, dirs := os.Getenv("SSL_CERT_FILE"), os.Getenv("SSL_CERT_DIR")
	if file == "" && dirs == "" {
		return nil, nil
	}
	roots := x509.NewCertPool()
	if file != "" {
		valid, err := appendCABundle(roots, file)
		if err != nil || !valid {
			return nil, errors.New("invalid SSL_CERT_FILE trust source")
		}
	}
	if dirs != "" {
		valid := false
		for _, dir := range filepath.SplitList(dirs) {
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) > maxCADirEntries {
				return nil, errors.New("invalid SSL_CERT_DIR trust source")
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".") || entry.IsDir() {
					continue
				}
				added, err := appendCABundle(roots, filepath.Join(dir, entry.Name()))
				if err != nil {
					return nil, errors.New("invalid SSL_CERT_DIR trust source")
				}
				valid = valid || added
			}
		}
		if !valid {
			return nil, errors.New("invalid SSL_CERT_DIR trust source")
		}
	}
	return roots, nil
}

func appendCABundle(pool *x509.CertPool, path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCABundleBytes {
		return false, errors.New("CA source must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCABundleBytes+1))
	if err != nil || len(data) > maxCABundleBytes {
		return false, errors.New("cannot read CA source")
	}
	return pool.AppendCertsFromPEM(data), nil
}
