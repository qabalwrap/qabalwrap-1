package qabalwrap

import (
	"encoding/json"
	"os"
	"path/filepath"

	identnormalize "github.com/nangantata/go-identnormalize"
)

// Content identifiers for marshaling and unmarshaling.
const (
	ContentIdentLocalServiceRef    = "local-service-ref"
	ContentIdentServiceRefs        = "service-refs"
	ContentIdentCertificateManager = "cert-manager"
)

type StateStore struct {
	folderPath     string
	fileNamePrefix string
}

func NewStateStore(folderPath, serviceType, serviceTextIdent string) (s *StateStore, err error) {
	if folderPath, err = filepath.Abs(folderPath); nil != err {
		return
	}
	if err = os.MkdirAll(folderPath, 0700); nil != err {
		return
	}
	serviceTextIdent = identnormalize.AlphabetNumberDashOnlyIdentifier(serviceTextIdent, MaxServiceIdentLength)
	if serviceTextIdent == "" {
		err = ErrEmptyIdentifier
		return
	}
	s = &StateStore{
		folderPath:     folderPath,
		fileNamePrefix: serviceType + "." + serviceTextIdent + ".",
	}
	return
}

func (s *StateStore) fileName(contentIdent string) string {
	return filepath.Join(s.folderPath, s.fileNamePrefix+contentIdent+".json")
}

func (s *StateStore) Unmarshal(contentIdent string, v interface{}) (ok bool, err error) {
	fp, err := os.Open(s.fileName(contentIdent))
	if nil != err {
		if os.IsNotExist(err) {
			return false, nil
		}
		return
	}
	defer fp.Close()
	decoder := json.NewDecoder(fp)
	if err = decoder.Decode(v); nil != err {
		return
	}
	return true, nil
}

func (s *StateStore) Marshal(contentIdent string, v interface{}) (err error) {
	fp, err := os.Create(s.fileName(contentIdent))
	if nil != err {
		return
	}
	defer fp.Close()
	encoder := json.NewEncoder(fp)
	if err = encoder.Encode(v); nil != err {
		return
	}
	return nil
}
