package qabalwrap

import (
	"context"
	"crypto/tls"
	"math"
	"sync"

	"google.golang.org/protobuf/proto"
)

// MaxServiceIdentLength define max length of service identifier.
const MaxServiceIdentLength = 128

const (
	PrimaryMessageSwitchServiceIdent   int = 0
	AssignableServiceIdentMin              = 1
	AssignableServiceIdentMax              = (8192 - 1)
	AccessProviderPeerServiceIdent         = math.MaxInt16 - 2
	MessageSwitchBroadcastServiceIdent     = math.MaxInt16 - 1
	UnknownServiceIdent                    = -1
)

type ContentEdgeProvider interface {
	ServiceProvider

	// Stop close all pending transfers.
	Stop()
}

type ContentFetchProvider interface {
	ServiceProvider
}

type AccessProvider interface {
	ServiceProvider
}

type MessageSender interface {
	// Send given message into message switch.
	Send(destServiceIdent int, messageContentType MessageContentType, messageContent proto.Message)

	// ServiceSerialIdentByTextIdent lookup service serial identifier with given text identifier.
	ServiceSerialIdentByTextIdent(textIdent string) (serialIdent int, hasReceiver, ok bool)
}

type MessageDispatcher interface {
	// DispatchMessage pass message into message switch.
	DispatchMessage(m *EnvelopedMessage)
}

type RelayProvider interface {
	// SetMessageDispatcher should update dispatcher for this instance if relay provider.
	// This method is invoked on register this instance with message switch.
	SetMessageDispatcher(dispatcher MessageDispatcher)

	// EmitMessage send given message through this provider.
	// Will invoke concurrently at operating stage.
	BlockingEmitMessage(envelopedMessage *EnvelopedMessage) (err error)

	// NonblockingEmitMessage send given message through this provider in non-blocking way.
	// Will invoke concurrently at operating stage.
	NonblockingEmitMessage(envelopedMessage *EnvelopedMessage) (emitSuccess bool)
}

type CertificateSubscriber interface {
	// UpdateHostTLSCertificates trigger host TLS update of service.
	// Should only invoke at maintenance thread in setup stage and runtime stage.
	UpdateHostTLSCertificates(waitGroup *sync.WaitGroup, tlsCerts []tls.Certificate) (err error)
}

type CertificateProvider interface {
	// RegisterHostTLSCertificates request certificates for given host names.
	// Should only invoke at maintenance thread in setup stage.
	RegisterHostTLSCertificates(hostNames []string, certSubscriber CertificateSubscriber) (hostTLSCertWatchTrackIdent int, err error)
}

// ServiceProvider define interface for services.
type ServiceProvider interface {
	// Setup prepare provider for operation.
	// Should only invoke at maintenance thread in setup stage.
	Setup(certProvider CertificateProvider) (err error)

	// Start service instance for operation.
	// Should only invoke at maintenance thread in setup stage.
	Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error)

	// Stop service instance,
	Stop()

	// ReceiveMessage deliver message into this instance of service provider.
	// The message should decypted before pass into this method.
	// Will invoke concurrently at operating stage.
	ReceiveMessage(envelopedMessage *EnvelopedMessage) (err error)

	// SetMessageSender bind given sender with this instance of service provider.
	SetMessageSender(messageSender MessageSender)

	// RelayProviders return associated relay providers if available.
	// Return nil if this service provider does not support relay service.
	RelayProviders() (relayProviders []RelayProvider)

	// SwitchAvailable is invoked when message switch is available.
	//SwitchAvailable()

	// RegisterAvailable is invoked when service register is available.
	//RegisterAvailable()

	// RegisterUpdated is invoked when records in service register is modified.
	//RegisterUpdated()
}
