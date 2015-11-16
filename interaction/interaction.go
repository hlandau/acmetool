// Package interaction provides facilities for asking the user questions, via
// dialogs or stdio.
package interaction

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
	Cancelled bool

	// Value the user entered, if applicable.
	Value string
}

// Specifies the initial parameters for a status dialog.
type StatusInfo struct {
	// Title to be used for the status dialog.
	Title string

	// The status line. This may contain multiple lines if desired.
	StatusLine string
}

// Used to control a status dialog.
type StatusSink interface {
	// Close the dialog and wait for it to terminate.
	Close() error

	// Set progress = (n/ofM)%.
	SetProgress(n, ofM int)

	// Set the status line(s). You cannot specify a number of lines that exceeds
	// the number of lines specified in the initial StatusLine.
	SetStatusLine(status string)
}

// An Interactor facilitates interaction with the user.
type Interactor interface {
	Prompt(*Challenge) (*Response, error)
	Status(*StatusInfo) (StatusSink, error)
}
