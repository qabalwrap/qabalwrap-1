package messageswitch

import (
	"crypto/rand"
	"log"
	"math"

	keybinary "github.com/go-marshaltemabu/go-keybinary"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"

	qabalwrap "github.com/qabalwrap/qabalwrap-1"
	qbw1grpcgen "github.com/qabalwrap/qabalwrap-1/gen/qbw1grpcgen"
)

// ServiceReference contains service identification and access keys.
type ServiceReference struct {
	UniqueIdent uuid.UUID             `json:"u"`
	SerialIdent int                   `json:"i"`
	TextIdent   string                `json:"t"`
	PublicKey   keybinary.ByteArray32 `json:"p"`
	PrivateKey  keybinary.ByteArray32 `json:"s"`
}

func findMaxServiceSerialIdent(refs []*ServiceReference) (maxSerialIdent int) {
	maxSerialIdent = math.MinInt32
	for _, r := range refs {
		if (r == nil) || !r.IsNormalSerialIdent() {
			continue
		}
		if r.SerialIdent > maxSerialIdent {
			maxSerialIdent = r.SerialIdent
		}
	}
	return
}

// generateServiceReference create new instance of ServiceReference.
// Required keys and UUID are generated as well.
func generateServiceReference(textIdent string) (ref *ServiceReference, err error) {
	pubKey, priKey, err := box.GenerateKey(rand.Reader)
	if nil != err {
		log.Printf("ERROR: (generateServiceReference) cannot generate asymmetric key: %v", err)
		return
	}
	ref = &ServiceReference{
		UniqueIdent: uuid.New(),
		SerialIdent: qabalwrap.UnknownServiceIdent,
		TextIdent:   textIdent,
		PublicKey:   *keybinary.NewByteArray32(pubKey),
		PrivateKey:  *keybinary.NewByteArray32(priKey),
	}
	return
}

func newServiceReferenceFromQBW1RPCServiceIdent(srvIdent *qbw1grpcgen.ServiceIdent) (ref *ServiceReference, err error) {
	srvUniqueIdent, err := uuid.Parse(srvIdent.UniqueIdent)
	if nil != err {
		log.Printf("ERROR: (newServiceReferenceFromQBW1RPCServiceIdent) cannot have given unique identifier parse: [%s] %v",
			srvIdent.UniqueIdent, err)
		return
	}
	ref = &ServiceReference{
		UniqueIdent: srvUniqueIdent,
		SerialIdent: int(srvIdent.SerialIdent),
		TextIdent:   srvIdent.TextIdent,
	}
	if err = ref.PublicKey.UnmarshalBinary(srvIdent.PublicKey); nil != err {
		log.Printf("ERROR: (newServiceReferenceFromQBW1RPCServiceIdent) cannot load public key [%s/%s]: %v", srvIdent.UniqueIdent, srvIdent.TextIdent, err)
		ref = nil
	}
	return
}

// IsNormalSerialIdent check if serial identifier value is located within assignable range.
func (ref *ServiceReference) IsNormalSerialIdent() bool {
	return (ref.SerialIdent >= qabalwrap.AssignableServiceIdentMin) && (ref.SerialIdent <= qabalwrap.AssignableServiceIdentMax)
}
