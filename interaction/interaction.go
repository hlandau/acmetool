package interaction

import "fmt"

type ResponseType int

const (
	// Acknowledgement only. Show notice and require user to acknowledge before
	// continuing. Response fields ignored.
	RTAcknowledge ResponseType = iota

	// Show notice and ask user to agree/disagree. Response has Cancelled set
	// if user disagreed.
	RTYesNo

	// Require user to enter a single-line string, returned as the Value of the
	// Response.
	RTLineString

	// Require user to select from a number of options.
	RTSelect
)

// A challenge prompt to be shown to the user.
type Challenge struct {
	// Title to be used for e.g. a dialog box if shown.
	Title string

	// The text to be shown to the user. May be multiple lines.
	Body string

	// Label to use for RTYesNo 'Yes' label.
	YesLabel string
	// Label to use for RTYesNo 'No' label.
	NoLabel string

	// Prompt line used for stdio prompts. For RTAcknowledge, defaults to 'Press
	// Return to continue.' or similar. For RTYesNo, defaults to 'Agree? [Yn]'
	// or similar.
	Prompt string

	// The response type.
	ResponseType ResponseType

	// Challenge type unique identifier. This identifies the meaning of the dialog
	// and can be used to respond automatically to known dialogs.
	UniqueID string

	// Specifies the options for RTSelect.
	Options []Option
}

// An option in an RTSelect challenge.
type Option struct {
	// Option title.
	Title string

	// Internal value that the option represents.
	Value string
}

type Response struct {
	// Set this to true if the user cancelled the challenge.
	// Will short circuit with ErrCancelled.
	Cancelled bool

	// Value the user entered, if applicable.
	Value string
}

var ErrCancelled = fmt.Errorf("user cancelled responder challenge")

// An Func is called by a responder when it needs to receive some sort
// of user input or acknowledgement. An Response is returned. Errors
// short circuit through the responder's Start function.
type Func func(*Challenge) (*Response, error)
