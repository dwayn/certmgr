package file

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"regexp"
	"strconv"
	"syscall"

	"github.com/cloudflare/certmgr/util"

	log "github.com/sirupsen/logrus"
)

var idRegexp = regexp.MustCompile(`^\d+$`)

// Path sanitized string path
type Path string

// File contains path and ownership information for a file.
type File struct {
	Path  string `json:"path" yaml:"path"`
	Owner string `json:"owner" yaml:"owner"`
	Group string `json:"group" yaml:"group"`
	Mode  string `json:"mode" yaml:"mode"`

	uid, gid int
	mode     os.FileMode
}

// NewFile constructor for file structs that handles parsing, lookup and
//	setting defaults for files
func NewFile(path, owner, group, mode string) (*File, error) {
	f := &File{
		Path:  path,
		Owner: owner,
		Group: group,
		Mode:  mode,
	}
	err := f.parse()
	if err != nil {
		return nil, err
	}
	return f, nil
}

// UnmarshalYAML implement yaml unmarshalling logic
func (f *File) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias File
	if err := unmarshal((*alias)(f)); err != nil {
		return err
	}
	return f.parse()
}

// UnmarshalJSON implement json unmarshalling logic
func (f *File) UnmarshalJSON(data []byte) error {
	type alias File
	if err := json.Unmarshal(data, (*alias)(f)); err != nil {
		return err
	}
	return f.parse()
}

// Parse sets up the File structure from its string parameters; the
// hint is used to provide a hint as to what file is being processed
// for use in error messages. This includes validating that the user
// and group referenced exist; providing sensible defaults, and
// processing the mode. The method is intended to allow set up after
// unmarshalling from a configuration file.
func (f *File) parse() (err error) {
	if f.Path == "" {
		return errors.New("missing path")
	}

	if f.Mode == "" {
		f.Mode = "0644"
	}

	var u *user.User
	if f.Owner == "" || f.Group == "" {
		u, err = user.Current()
		if err != nil {
			return err
		}

		if f.Owner == "" {
			f.Owner = u.Uid
		}

		if f.Group == "" {
			f.Group = u.Gid
		}
	}

	if idRegexp.MatchString(f.Owner) {
		f.uid, err = strconv.Atoi(f.Owner)
		if err != nil {
			return err
		}
	} else {
		if u == nil {
			u, err = user.Lookup(f.Owner)
			if err != nil {
				return err
			}

			f.uid, err = strconv.Atoi(u.Uid)
			if err != nil {
				return err
			}
		}
	}

	if idRegexp.MatchString(f.Group) {
		f.gid, err = strconv.Atoi(f.Group)
		if err != nil {
			return err
		}
	} else {
		var g *user.Group
		g, err = user.LookupGroup(f.Group)
		if err != nil {
			return err
		}

		f.gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return err
		}
	}

	mode, err := strconv.ParseUint(f.Mode, 0, 32)
	if err != nil {
		return err
	}

	f.mode = os.FileMode(mode)
	return nil
}

// CheckPermissions checks that the permissions on disk match what we intend.  If the
// file doesn't exist, then the raw error for stat is returned.
func (f *File) CheckPermissions() error {
	st, err := os.Stat(f.Path)
	if err != nil {
		return err
	}

	if st.Mode() != f.mode {
		return fmt.Errorf("mode has changed from %s to %s", f.mode, st.Mode())
	}

	unixStat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		// yes, this is noisy on windows.  Don't think we have windows users however...
		log.Warningf("Certmgr doesn't know how to verify ownership for %s", f.Path)
		return nil
	}

	if unixStat.Uid != uint32(f.uid) {
		return fmt.Errorf("uid has changed from %d to %d", uint32(f.uid), unixStat.Uid)
	}
	if unixStat.Gid != uint32(f.gid) {
		return fmt.Errorf("uid has changed from %d to %d", uint32(f.uid), unixStat.Gid)
	}
	return nil
}

// ReadFile read contents from the file on disk if it exists
func (f *File) ReadFile() ([]byte, error) {
	return ioutil.ReadFile(f.Path)
}

// WriteFile write given content to disk with the appropriate permissions and mode
func (f *File) WriteFile(data []byte) error {
	tmpFile, err := ioutil.TempFile(path.Dir(f.Path), path.Base(f.Path))
	if err != nil {
		return err
	}
	defer func() {
		if tmpFile != nil {
			os.Remove(tmpFile.Name())
		}
	}()

	err = tmpFile.Chown(f.uid, f.gid)
	if err != nil {
		return err
	}

	err = tmpFile.Chmod(f.mode)
	if err != nil {
		return err
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		return err
	}
	err = os.Rename(tmpFile.Name(), f.Path)
	if err != nil {
		return err
	}
	tmpFile = nil
	return nil
}

// Unlink deletes the file specified by the Path field.
func (f *File) Unlink() error {
	log.Debugf("removing %s", f.Path)
	err := os.Remove(f.Path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (f *File) String() string {
	return f.Path
}

// NewCertificateFile constructor for file structs that handles parsing, lookup and
//	setting defaults for files
func NewCertificateFile(path, owner, group, mode string) (*CertificateFile, error) {
	f := &CertificateFile{
		File{
			Path:  path,
			Owner: owner,
			Group: group,
			Mode:  mode,
		},
	}
	err := f.parse()
	if err != nil {
		return nil, err
	}
	return f, nil
}

// CertificateFile is a convenience wrapper of File
type CertificateFile struct {
	File
}

// ReadCertificate read and parse the on disk certificate
func (cf *CertificateFile) ReadCertificate() (*x509.Certificate, error) {
	data, err := cf.ReadFile()
	if err != nil {
		return nil, err
	}
	pemData, _ := pem.Decode(data)
	if pemData == nil {
		return nil, errors.New("Unable to pem decode certificate")
	}
	return x509.ParseCertificate(pemData.Bytes)
}

// WriteCertificate serialize and write a certificate to disk
func (cf *CertificateFile) WriteCertificate(cert *x509.Certificate) error {
	return cf.WriteFile(util.EncodeCertificateToPEM(cert))
}

// UnmarshalYAML implement yaml unmarshalling logic
func (cf *CertificateFile) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshal(&(cf.File))
}

// UnmarshalJSON implement json unmarshalling logic
func (cf *CertificateFile) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &(cf.File))
}
