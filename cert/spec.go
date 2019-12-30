// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/yaml.v2"

	"github.com/cenkalti/backoff"
	"github.com/cloudflare/certmgr/cert/storage"
	"github.com/cloudflare/certmgr/file"
	"github.com/cloudflare/certmgr/util"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
	log "github.com/sirupsen/logrus"
)

// These are defaults used for limiting the backoff logic for cfssl transport
const backoffMaxDelay = time.Minute * 2

//
// DefaultInterval is used if no duration is provided for a
// Manager. This defaults to one hour.
const DefaultInterval = time.Hour

// DefaultBefore is used if no duration is provided for a
// Manager. This defaults to 72 hours.
const DefaultBefore = time.Hour * 72

// SpecOptions is a struct used for holding defaults used for instantiating a spec.
type SpecOptions struct {
	// This defines the service manager to use.  This should be defined
	// globally rather than per cert- it's allowed here to allow cert
	// definitions to use a servicemanager of 'command' to allow freeform
	// invocations.
	ServiceManagerName string `json:"svcmgr" yaml:"svcmgr"`

	// ServiceManagerTakeActionOnlyIfRunning if set to truee, disables reload/restart attempts
	// if the target isn't running.  If the service manager service in use isn't a service manager- for example,
	// a raw command- this directive does nothing.
	ServiceManagerTakeActionOnlyIfRunning bool `json:"take_actions_only_if_running" yaml:"take_actions_only_if_running"`

	// Before is how long before the cert expires to start
	// attempting to renew it.  If unspecified, the manager default is used.
	Before time.Duration

	// Interval is how often to update the NextExpires metric.
	Interval time.Duration

	// IntervalSplay is a randomized Duration between 0 and IntervalSplay that is added to each interval
	// to distribute client load across time.  The bounding of a clients wake is [Interval, Interval + IntervalSplay]
	IntervalSplay time.Duration

	// InitialSplay is a randomized Duration between [0, InitialSplay] to sleep after the first PKI check.
	// This is Primarily useful to force an initial randomization if many ndoes with certmgr are restarted all
	// at the same time.
	InitialSplay time.Duration

	// Remote is shorthand for updating CA.Remote for instantiation.
	// This specifies the remote upstream to talk to.
	Remote string `json:"remote" yaml:"remote"`
}

// ParsableSpecOptions is a struct that supports full deserialization of SpecOptions including time.Duration
// fields (which <go-2 doesn't support, but yaml.v2 mostly does)
// Clients should use this struct for unmarshall invocations, and do a .FinalizeSpecOptionParsing()
// invocation to backfill the SpecOptions.
type ParsableSpecOptions struct {
	SpecOptions

	// ParsedBefore is used to update the SpecOptions.Before field.
	ParsedBefore util.ParsableDuration `json:"before" yaml:"before"`

	// ParsedInterval is used to update the SpecOptions.Interval field.
	ParsedInterval util.ParsableDuration `json:"interval" yaml:"interval"`

	// ParsedIntervalSplay is used to update the SpecOptions.IntervalSplay field.
	ParsedIntervalSplay util.ParsableDuration `json:"interval_splay" yaml:"interval_splay"`

	// ParsedInitialSplay is used to update the SpecOptions.InitialSplay field.
	ParsedInitialSplay util.ParsableDuration `json:"initial_splay" yaml:"initial_splay"`
}

// FinalizeSpecOptionParsing backfills the embedded SpecOptions structure with values parsed during unmarshall'ing.
// This should be invoked before you pass SpecOptions to other consumers.
// If you've created your SpecOptions directly, then you can (and should) ignore this method.
func (p *ParsableSpecOptions) FinalizeSpecOptionParsing() {
	if p.ParsedBefore != 0 {
		p.Before = time.Duration(p.ParsedBefore)
	}
	if p.ParsedInterval != 0 {
		p.Interval = time.Duration(p.ParsedInterval)
	}
	if p.ParsedIntervalSplay != 0 {
		p.IntervalSplay = time.Duration(p.ParsedIntervalSplay)
	}
	if p.ParsedInitialSplay != 0 {
		p.InitialSplay = time.Duration(p.ParsedInitialSplay)
	}
}

// A Spec contains information needed to monitor and renew a
// certificate.
type Spec struct {
	ParsableSpecOptions

	// The service is the service that uses this certificate. If
	// this field is not empty, the action below will be applied
	// to this service upon certificate renewal. It can also be
	// used to describe what this certificate is for.
	Service string `json:"service" yaml:"service"`

	// Action is one of empty, "nop", "reload", or "restart" (see
	// the svcmgr package for details).
	Action string `json:"action" yaml:"action"`

	// Request contains the CSR metadata needed to request a
	// certificate.
	Request *csr.CertificateRequest `json:"request" yaml:"request"`

	// Key contains the file metadata for the private key.
	Key *file.File `json:"private_key" yaml:"private_key"`

	// Cert contains the file metadata for the certificate.
	Cert *file.CertificateFile `json:"certificate" yaml:"certificate"`

	// CA specifies the certificate authority that should be used.
	CA CA `json:"authority" yaml:"authority"`

	// Path points to the on-disk location of the certificate
	// spec.
	Path string

	tr *transport.Transport

	// used for tracking when the spec was read
	loadTime time.Time

	expiry struct {
		CA   time.Time
		Cert time.Time
	}

	Storage storage.PKIStorage
}

func (spec *Spec) String() string {
	return spec.Path
}

// Paths returns the paths that this spec is responsible for on disk
func (spec *Spec) Paths() []string {
	x := []string{}
	if spec.CA.File != nil {
		x = append(x, spec.CA.File.Path)
	}
	if spec.Cert != nil {
		x = append(x, spec.Cert.Path)
		x = append(x, spec.Key.Path)
	}
	return x
}

// Identity creates a transport package identity for the certificate.
func (spec *Spec) identity() (*core.Identity, error) {
	ident := &core.Identity{
		Request: spec.Request,
		Roots: []*core.Root{
			&core.Root{
				Type: "system",
			},
			&core.Root{
				Type: "cfssl",
				Metadata: map[string]string{
					"host":          spec.CA.Remote,
					"profile":       spec.CA.Profile,
					"label":         spec.CA.Label,
					"tls-remote-ca": spec.CA.RootCACert,
				},
			},
		},
		Profiles: map[string]map[string]string{
			"cfssl": map[string]string{
				"remote":        spec.CA.Remote,
				"profile":       spec.CA.Profile,
				"label":         spec.CA.Label,
				"tls-remote-ca": spec.CA.RootCACert,
			},
		},
	}

	authkey := spec.CA.AuthKey
	if spec.CA.AuthKeyFile != "" {
		log.Debugf("loading auth_key_file %v", spec.CA.AuthKeyFile)
		content, err := ioutil.ReadFile(spec.CA.AuthKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed reading auth_key_file %v: %v", spec.CA.AuthKeyFile, err)
		}
		authkey = strings.TrimSpace(string(content))
	}
	if authkey != "" {
		ident.Profiles["cfssl"]["auth-type"] = "standard"
		ident.Profiles["cfssl"]["auth-key"] = authkey
	}

	return ident, nil
}

// loadFromPath load and fill this spec from the given pathway
// If this invocation returns an error, the spec instance should be discarded
// and recreated.
func (spec *Spec) loadFromPath(path string) error {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	specStat, err := os.Stat(path)
	if err != nil {
		// Hit the race; we read the file but someone wiped it.
		return err
	}

	switch filepath.Ext(path) {
	case ".json":
		err = util.StrictJSONUnmarshal(in, &spec)
	case ".yml", ".yaml":
		err = yaml.UnmarshalStrict(in, &spec)
	default:
		err = fmt.Errorf("unrecognised spec file format for %s", path)
	}

	if err == nil {
		spec.loadTime = specStat.ModTime()
		spec.Path = path
	}
	return err
}

// Load reads a spec from a JSON configuration file.
func Load(path string, defaults *SpecOptions) (*Spec, error) {
	var spec = &Spec{
		Request: csr.New(),
	}
	if defaults != nil {
		spec.SpecOptions = *defaults
	}
	if spec.Before == 0 {
		spec.Before = DefaultBefore
	}
	if spec.Interval == 0 {
		spec.Interval = DefaultInterval
	}

	err := spec.loadFromPath(path)
	if err != nil {
		return nil, err
	}

	// transfer the parsed durations into their final resting spot.
	spec.FinalizeSpecOptionParsing()

	if spec.CA.Remote == "" {
		spec.CA.Remote = spec.Remote
	}

	if spec.CA.Remote == "" {
		return nil, errors.New("no remote specified in authority (either in the spec or in the certmgr config)")
	}

	fb, err := storage.NewFileBackend(spec.CA.File, spec.Cert, spec.Key)
	if err != nil {
		return nil, err
	}

	if spec.ServiceManagerName == "" || spec.ServiceManagerName == "dummy" {
		log.Debugf("no notification backend configured for %s", spec)
		spec.Storage = fb
	} else {
		if spec.ServiceManagerName == "command" {
			log.Debugf("creating command notifier for %s", spec)
			if spec.Service != "" {
				return nil, fmt.Errorf("svcmgr backend of 'command' doesn't support the 'service' field; got %s", spec.Service)
			}
			spec.Storage, err = storage.NewFileCommandNotifier(fb, spec.Action)
			err = errors.WithMessage(err, "while instantiating command notifier")
		} else {
			log.Debugf("creating service notifier for %s", spec)
			// assume it's sysv/systemd
			spec.Storage, err = storage.NewFileServiceNotifier(
				fb,
				spec.ServiceManagerName,
				&storage.FileServiceOptions{
					Action:            spec.Action,
					Service:           spec.Service,
					CheckTargetStatus: spec.ServiceManagerTakeActionOnlyIfRunning,
				},
			)
			err = errors.WithMessage(err, "while instantiating service notifier")
		}
	}
	if err != nil {
		return nil, err
	}

	identity, err := spec.identity()
	if err != nil {
		return nil, err
	}

	spec.tr, err = transport.New(spec.Before, identity)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

// Lifespan returns a time.Duration for the certificate's validity.
func (spec *Spec) Lifespan() time.Duration {
	t := spec.expiry.CA
	if t.After(spec.expiry.Cert) {
		t = spec.expiry.Cert
	}
	return time.Now().Sub(t)
}

// warnIfHasChangedOnDisk logs warnings if the spec in memory doesn't reflect what's on disk.
func (spec *Spec) warnIfHasChangedOnDisk() {
	specStat, err := os.Stat(spec.Path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warningf("spec %s was removed from on disk", spec)
		} else {
			log.Warningf("spec %s failed to be checked on disk: %s", spec, err)
		}
	} else if specStat.ModTime().After(spec.loadTime) {
		log.Warningf("spec %s has changed on disk", spec)
	} else {
		log.Debugf("spec %s hasn't changed on disk", spec)
	}
}

// CertExpireTime returns the time at which this spec's Certificate is no
// longer valid.
func (spec *Spec) CertExpireTime() time.Time {
	return spec.expiry.Cert
}

// CAExpireTime returns the time at which this spec's CA is no
// longer valid.
func (spec *Spec) CAExpireTime() time.Time {
	return spec.expiry.CA
}

func (spec *Spec) validateStoredPKI(currentCA *x509.Certificate) error {

	existingCA, keyPair, err := spec.Storage.Load()
	if err != nil {
		return errors.WithMessage(err, "stored PKI is invalid")
	}
	spec.updateCAExpiry(currentCA.NotAfter)

	if existingCA != nil {
		if !existingCA.Equal(currentCA) {
			return errors.New("stored CA is out of date with new CA")
		}
	}
	if !spec.Storage.WantsKeyPair() {
		// nothing further to check
		return nil
	}
	if keyPair.Leaf == nil {
		// tls.LoadX509KeyPair doesn't retain leaf, force the reparse
		leaf, err := x509.ParseCertificate(keyPair.Certificate[len(keyPair.Certificate)-1])
		if err != nil {
			return errors.WithMessage(err, "failed parsing stored certificate")
		}
		keyPair.Leaf = leaf
	}
	// update internal metrics
	spec.updateCertExpiry(keyPair.Leaf.NotAfter)

	err = util.CertificateChainVerify(currentCA, keyPair.Leaf)
	if err != nil {
		return errors.WithMessage(err, "stored cert failed CA check")
	}

	// confirm that pkix is the same.  This catches things like OU being changed; these are slices
	// of slices and there isn't a usable equality check, thus the .String() usage.
	if spec.Request.Name().String() != keyPair.Leaf.Subject.String() {
		return fmt.Errorf("spec subject has changed: was %s, now is %s", keyPair.Leaf.Subject, spec.Request.Name())
	}

	if !util.CertificateMatchesHostname(spec.Request.Hosts, keyPair.Leaf) {
		return errors.New("spec DNS name has changed")
	}

	// validate that the cert isn't expired and is still valid.
	now := time.Now()
	if now.After(keyPair.Leaf.NotAfter) {
		return fmt.Errorf("certificate already expired at %s", keyPair.Leaf.NotAfter)
	}
	now = now.Add(spec.tr.Before)
	if now.After(keyPair.Leaf.NotAfter) {
		return fmt.Errorf("certificate is within the renewal threshold of %s: %s", spec.tr.Before, keyPair.Leaf.NotAfter)
	}
	if keyPair.Leaf.NotBefore.After(now) {
		// someone needs a better clock.
		return fmt.Errorf("certificate isn't yet valid: %s", keyPair.Leaf.NotBefore)
	}
	return spec.validatePrivKey(keyPair.PrivateKey)
}

func (spec *Spec) validatePrivKey(privateKey interface{}) error {
	verify := func(algo string, size int) error {
		if spec.Request.KeyRequest.Algo() != algo {
			return fmt.Errorf("key algo is %s, must be %s", algo, spec.Request.KeyRequest.Algo())
		}
		if spec.Request.KeyRequest.Size() != size {
			return fmt.Errorf("key size is %d, must be %d", size, spec.Request.KeyRequest.Size())
		}
		return nil
	}

	switch key := privateKey.(type) {
	case (*rsa.PrivateKey):
		return verify("rsa", key.N.BitLen())
	case (*ecdsa.PrivateKey):
		return verify("ecdsa", key.Curve.Params().BitSize)
	}
	return fmt.Errorf("unsupported key algorithm: %T", privateKey)
}

// UpdateIfNeeded performs a refresh only if PKI is in need of a refresh (expired, new CA, etc)
func (spec *Spec) UpdateIfNeeded() error {
	ca, err := spec.getCurrentCA()
	if err != nil {
		return err
	}
	err = spec.validateStoredPKI(ca)
	if err == nil {
		log.Debugf("spec %s is still valid", spec)
		return nil
	}
	log.Infof("spec %s is needs refresh: %s", spec, err)
	return spec.doRefresh(ca)
}

// ForceUpdate forces a refresh of the PKI content
func (spec *Spec) ForceUpdate() error {
	ca, err := spec.getCurrentCA()
	if err != nil {
		return err
	}
	log.Infof("refresh was forced for %s", spec)
	return spec.doRefresh(ca)
}

func (spec *Spec) doRefresh(currentCA *x509.Certificate) error {
	var keyPair *tls.Certificate
	var err error

	log.Debugf("performing refresh for %s", spec)

	if spec.Storage.WantsKeyPair() {
		log.Debugf("spec %s: uses keyPairs, fetching", spec)
		keyPair, err = spec.fetchNewKeyPair()
		if err != nil {
			return errors.WithMessage(err, "while fetching new keyPair")
		}
	}
	log.Debugf("spec %s: storing content", spec)
	return errors.WithMessage(
		spec.writePKIToStorage(currentCA, keyPair),
		"storing PKI",
	)
}

func (spec *Spec) getCurrentCA() (*x509.Certificate, error) {
	ca, err := spec.CA.getRemoteCert()
	err = errors.WithMessagef(err, "requested CA for spec %s", spec)
	if err != nil {
		SpecRequestFailureCount.WithLabelValues(spec.Path).Inc()
	}
	return ca, err
}

func (spec *Spec) writePKIToStorage(ca *x509.Certificate, keyPair *tls.Certificate) error {
	SpecWriteCount.WithLabelValues(spec.Path).Inc()

	err := spec.Storage.Store(ca, keyPair)
	if err != nil {
		SpecWriteFailureCount.WithLabelValues(spec.Path).Inc()
		return err
	}
	spec.updateCAExpiry(ca.NotAfter)
	spec.updateCertExpiry(keyPair.Leaf.NotAfter)
	return nil
}

// fetchNewKeyPair request a fresh certificate/key from the transport, backing off as needed.
func (spec *Spec) fetchNewKeyPair() (*tls.Certificate, error) {

	// use exponential backoff rather than using cfssl's backoff implementation; that implementation
	// can back off up to an hour before returning control back to the invoker; that isn't
	// desirable.  If we can't get the requests in in a timely fahsion, we'll wake up and
	// revisit via our own scheduling.

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = backoffMaxDelay
	err := backoff.Retry(
		func() error {

			err := spec.tr.RefreshKeys()
			if err != nil {
				SpecRequestFailureCount.WithLabelValues(spec.Path).Inc()
				if isAuthError(err) {
					log.Errorf("spec %s: invalid auth key.  Giving up", spec)
					err = backoff.Permanent(errors.New("invalid auth key"))
				} else {
					log.Warningf("spec %s: failed fetching new cert: %s", spec, err)
				}
			}
			return err
		},
		b,
	)

	if err != nil {
		return nil, errors.WithMessage(err, "while fetching certificate/key")
	}

	pair, err := spec.tr.Provider.X509KeyPair()
	if err != nil {
		log.Errorf("spec %s: likely internal error, fetched new cert/key but couldn't create a keypair from it: %s", spec, err)
	}
	return &pair, err
}

func (spec *Spec) updateCertExpiry(notAfter time.Time) {
	spec.expiry.Cert = notAfter
	SpecExpires.WithLabelValues(spec.Path, "cert").Set(float64(notAfter.Unix()))
}

func (spec *Spec) updateCAExpiry(notAfter time.Time) {
	spec.expiry.CA = notAfter
	SpecExpires.WithLabelValues(spec.Path, "ca").Set(float64(notAfter.Unix()))
}

// Run starts monitoring and enforcement of this spec's on disk PKI.
func (spec *Spec) Run(ctx context.Context) {
	// initialize our run   At this point an observer knows this spec is 'alive' and being enforced.
	SpecExpiresBeforeThreshold.WithLabelValues(spec.Path).Set(float64(spec.Before.Seconds()))

	// cleanup our runtime metrics on the way out so the observer knows we're no longer enforcing.
	defer spec.WipeMetrics()

	err := spec.UpdateIfNeeded()
	if err != nil {
		log.Errorf("spec %s: continuing despite failed initial validation due to %s", spec, err)
	}

	rng := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	sleepPeriod := spec.Interval
	if spec.InitialSplay != 0 {
		sleepPeriod = time.Duration(rng.Float64() * float64(spec.InitialSplay.Nanoseconds()))
		log.Infof("spec %s: initial splay will be used.", spec)
	}
	for {
		log.Infof("spec %s: Next check will be in %s", spec, sleepPeriod)
		SpecNextWake.WithLabelValues(spec.Path).Set(float64(time.Now().Add(sleepPeriod).Unix()))

		select {
		case <-time.After(sleepPeriod):
			log.Debugf("spec %s: woke, starting enforcement", spec)
			// log notifications if we're out of sync with disk; operator has to handle this, we can't
			// make the decision
			spec.warnIfHasChangedOnDisk()

			err := spec.UpdateIfNeeded()
			if err != nil {
				log.Errorf("failed processing %s due to %s", spec, err)
			}
			sleepPeriod = spec.Interval
			if spec.IntervalSplay != 0 {
				i := sleepPeriod.Nanoseconds()
				i += int64(rng.Float64() * float64(spec.IntervalSplay.Nanoseconds()))
				sleepPeriod = time.Duration(int64(i))
			}
		case <-ctx.Done():
			log.Debugf("spec %s: stopping monitoring due to %s", spec, ctx.Err())
			return
		}
	}
}
