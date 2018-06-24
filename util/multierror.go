package util

import "fmt"

// Used to return multiple errors, for example when several targets cannot be
// reconciled. This prevents one failing target from blocking others.
type MultiError []error

func (merr MultiError) Error() string {
	s := ""
	for _, e := range merr {
		if s != "" {
			s += "; \n"
		}
		s += e.Error()
	}
	return "the following errors occurred:\n" + s
}

// Used to return an error that wraps another error.
type WrapError struct {
	Msg string
	Sub error
}

// Create a new error that wraps another error.
func NewWrapError(sub error, msg string, args ...interface{}) *WrapError {
	return &WrapError{
		Msg: fmt.Sprintf(msg, args...),
		Sub: sub,
	}
}

func (werr *WrapError) Error() string {
	return fmt.Sprintf("%s [due to inner error: %v]", werr.Msg, werr.Sub)
}

// PertError knows whether it's temporary or not.
type PertError struct {
	error
	temporary bool
}

// Create an error that knows whether it's temporary or not.
func NewPertError(isTemporary bool, sub error) error {
	return &PertError{sub, isTemporary}
}

// Returns true iff the error is temporary. Compatible with the Temporary
// method of the "net" package's OpError type.
func (e *PertError) Temporary() bool {
	return e.temporary
}

type tmp interface {
	Temporary() bool
}

// Returns whether an error is temporary or not. An error is temporary if it
// implements the interface { Temporary() bool } and that method returns true.
// Errors which don't implement this interface aren't temporary.
func IsTemporary(err error) bool {
	x, ok := err.(tmp)
	if !ok {
		return false
	}

	return x.Temporary()
}
