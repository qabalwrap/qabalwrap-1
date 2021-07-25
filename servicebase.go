package qabalwrap

import (
	"context"
	"sync"
)

// ServiceBase offer base implementation of services.
// All services should embed this struct.
type ServiceBase struct{}

// Setup prepare provider for operation.
// Should only invoke at maintenance thread in setup stage.
func (s *ServiceBase) Setup(certProvider CertificateProvider) (err error) {
	return
}

// Start service instance for operation.
// Should only invoke at maintenance thread in setup stage.
func (s *ServiceBase) Start(ctx context.Context, waitGroup *sync.WaitGroup) (err error) {
	return
}

// Stop service instance,
func (s *ServiceBase) Stop() {}

// ReceiveMessage deliver message into this instance of service provider.
// The message should decypted before pass into this method.
func (s *ServiceBase) ReceiveMessage(rawMessage *EnvelopedMessage) (err error) {
	return
}

// SetMessageSender bind given sender with this instance of service provider.
func (s *ServiceBase) SetMessageSender(messageSender MessageSender) {}

// RelayProviders return associated relay providers if available.
// Return nil if this service provider does not support relay service.
func (s *ServiceBase) RelayProviders() (relayProviders []RelayProvider) {
	return
}
