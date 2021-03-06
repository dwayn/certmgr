package storage

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/certmgr/file"
	"github.com/cloudflare/certmgr/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// FileBackend is used for storing PKI content to disk and enforcing permissions.
type FileBackend struct {
	ca   *file.CertificateFile
	cert *file.CertificateFile
	key  *file.File
}

// NewFileBackend creates a storage backend used for writing CA/keypair's to disk.
func NewFileBackend(ca *file.CertificateFile, cert *file.CertificateFile, key *file.File) (*FileBackend, error) {
	if (cert == nil) != (key == nil) {
		return nil, errors.New("if either cert or key are defined, both fields must be defined as must request to successfully write the keypair to disk")
	}
	// check that we actually have something to do
	if ca == nil && cert == nil {
		return nil, errors.New("No CAFile nor CertFile was specified- nothing for this backend to do")
	}
	fb := &FileBackend{
		ca:   ca,
		cert: cert,
		key:  key,
	}
	err := fb.verifyUniquePaths()
	if err != nil {
		fb = nil
	}
	return fb, err
}

func (fb *FileBackend) String() string {
	return fmt.Sprintf(
		"file backend: CA=%s, cert=%s, key=%s",
		fb.ca,
		fb.cert,
		fb.key,
	)
}

func (fb *FileBackend) verifyUniquePaths() error {
	// ensure the backend doesn't point the CA/key/cert at the same files.  And yes, this is quadratic- it's limited to max 3 however.
	paths := fb.GetPaths()
	for idx := range paths {
		for subidx := range paths {
			if idx != subidx && paths[idx] == paths[subidx] {
				return fmt.Errorf("backend storage path %s isn't unique", paths[idx])
			}
		}
	}
	return nil
}

// WantsKeyPair indicates if this backend stores keypairs or not
func (fb *FileBackend) WantsKeyPair() bool {
	return fb.cert != nil
}

// GetPaths returns the paths that this backend manages
func (fb *FileBackend) GetPaths() []string {
	paths := []string{}
	if fb.ca != nil {
		paths = append(paths, fb.ca.Path)
	}
	if fb.WantsKeyPair() {
		paths = append(paths, fb.cert.Path)
		paths = append(paths, fb.key.Path)
	}
	return paths
}

// Load loads any PKI that this backend has on disk, checking that permissions are correct- erroring
// if content is missing that is expected, or permissions don't align.
func (fb *FileBackend) Load() (*x509.Certificate, *tls.Certificate, error) {
	log.Debugf("loading PKI material for %s", fb)
	var ca *x509.Certificate
	var err error
	fail := func(err error) (*x509.Certificate, *tls.Certificate, error) { return nil, nil, err }

	if fb.ca != nil {
		ca, err = fb.ca.ReadCertificate()
		if err != nil {
			return fail(errors.WithMessagef(err, "CA file %s", fb.ca.Path))
		}
		err = fb.ca.CheckPermissions()
		if err != nil {
			return fail(errors.WithMessagef(err, "CA file %s", fb.ca.Path))
		}
	}

	if !fb.WantsKeyPair() {
		return ca, nil, nil
	}

	keyPair, err := tls.LoadX509KeyPair(fb.cert.Path, fb.key.Path)
	if err != nil {
		return fail(errors.WithMessagef(err, "keyPair cert %s, key %s", fb.cert.Path, fb.key.Path))
	}

	// validate permissions.
	err = fb.cert.CheckPermissions()
	if err != nil {
		return fail(errors.WithMessagef(err, "cert file %s", fb.cert.Path))
	}
	err = fb.key.CheckPermissions()
	if err != nil {
		return fail(errors.WithMessagef(err, "key file %s", fb.key.Path))

	}
	return ca, &keyPair, nil
}

// Store writes new PKI content to disk, enforcing permissions.
func (fb *FileBackend) Store(ca *x509.Certificate, keyPair *tls.Certificate) error {
	log.Infof("persisting PKI for %v", fb)
	if fb.ca != nil {
		err := fb.ca.WriteCertificate(ca)
		if err != nil {
			return errors.WithMessagef(err, "failed writing CA to disk")
		}
	}

	if !fb.WantsKeyPair() {
		// nothing further to do.
		return nil
	}

	keyData, err := util.EncodeKeyToPem(keyPair.PrivateKey)
	if err == nil {
		return err
	}

	err = fb.cert.WriteCertificate(keyPair.Leaf)
	if err != nil {
		return errors.WithMessagef(err, "failed writing certificate to disk")
	}
	err = fb.key.WriteFile(keyData)

	if err != nil {
		return errors.WithMessage(err, "failed writing key to disk")
	}
	return nil
}
