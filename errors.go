package aiagentblocklist

import (
	"errors"
	"fmt"
)

// Sentinel errors. Every error returned by this package is an *Error whose
// Is method matches one of these, so callers can write
// errors.Is(err, aiagentblocklist.ErrAccessEnded).
var (
	// ErrNotFound means HTTP 404: the token or the file name is unknown.
	ErrNotFound = errors.New("aiagentblocklist: not found (unknown token or file)")
	// ErrAccessEnded means HTTP 403: the subscription has ended or is paused.
	ErrAccessEnded = errors.New("aiagentblocklist: access ended (subscription ended or paused)")
	// ErrHTTP means any other non-2xx HTTP status.
	ErrHTTP = errors.New("aiagentblocklist: unexpected HTTP status")
	// ErrToken means the download token is missing or not 32 letters and digits.
	ErrToken = errors.New("aiagentblocklist: invalid token")
	// ErrFileName means the requested file name is not a valid feed file name.
	ErrFileName = errors.New("aiagentblocklist: invalid file name")
)

// Error is the error type returned by the client. It plays the role of the
// AiAgentBlocklistError base type in the other language clients.
//
// Status is the HTTP status code, or 0 when no HTTP answer was received
// (bad token, bad file name, network failure, file system failure).
// Kind is one of the sentinel errors above, or nil for network, file
// system and parse failures. Err is the underlying cause, if any.
type Error struct {
	Status  int
	Message string
	Kind    error
	Err     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	msg := "aiagentblocklist: " + e.Message
	if e.Status != 0 {
		msg = fmt.Sprintf("%s (HTTP %d)", msg, e.Status)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying cause, such as a *url.Error or a
// context.DeadlineExceeded value.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is the sentinel error that classifies e.
func (e *Error) Is(target error) bool {
	return e.Kind != nil && target == e.Kind
}

func statusError(status int, name string) error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == 404:
		return &Error{Status: status, Message: "unknown token or file name for " + name, Kind: ErrNotFound}
	case status == 403:
		return &Error{Status: status, Message: "the subscription has ended or is paused", Kind: ErrAccessEnded}
	default:
		return &Error{Status: status, Message: "unexpected answer for " + name, Kind: ErrHTTP}
	}
}
