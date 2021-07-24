package messageswitch

import (
	"errors"
	"strconv"
)

// ErrNotHavingMessageSwitchServiceRecord indicate service record cannot be reach.
var ErrNotHavingMessageSwitchServiceRecord = errors.New("cannot reach message switch service")

// ErrNotSupportedOperation indicate service is not support given request.
var ErrNotSupportedOperation = errors.New("request operation is not support")

// ErrSourceServiceIdentNotFound indicate given source service ident reference to non-existed service.
type ErrSourceServiceIdentNotFound int

func (e ErrSourceServiceIdentNotFound) Error() string {
	return "[ErrSourceServiceIdentNotFound: " + strconv.FormatInt(int64(e), 10) + "]"
}

// ErrSourceServiceIdentOutOfRange indicate given source service ident not in the valid range.
type ErrSourceServiceIdentOutOfRange int

func (e ErrSourceServiceIdentOutOfRange) Error() string {
	return "[ErrSourceServiceIdentOutOfRange: " + strconv.FormatInt(int64(e), 10) + "]"
}

// ErrDestinationServiceIdentNotFound indicate given destination service ident reference to non-existed service.
type ErrDestinationServiceIdentNotFound int

func (e ErrDestinationServiceIdentNotFound) Error() string {
	return "[ErrDestinationServiceIdentNotFound: " + strconv.FormatInt(int64(e), 10) + "]"
}

// ErrDestinationServiceIdentOutOfRange indicate given destination service ident not in the valid range.
type ErrDestinationServiceIdentOutOfRange int

func (e ErrDestinationServiceIdentOutOfRange) Error() string {
	return "[ErrDestinationServiceIdentOutOfRange: " + strconv.FormatInt(int64(e), 10) + "]"
}

// ErrRelayLinksUnreachable indicate all relay providers in given service ident not reachable.
type ErrRelayLinksUnreachable int

func (e ErrRelayLinksUnreachable) Error() string {
	return "[ErrRelayLinksUnreachable: " + strconv.FormatInt(int64(e), 10) + "]"
}
