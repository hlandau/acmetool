// Package interaction provides facilities for asking the user questions, via
// dialogs or stdio.
package interaction

// Interaction mode. Specifies the type of response requested from the user.
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
	ResponseType ResponseType // The response type.

	Title string // Title to be used for e.g. a dialog box if shown.
	Body  string // The text to be shown to the user. May be multiple lines.

	YesLabel string // Label to use for RTYesNo 'Yes' label.
	NoLabel  string // Label to use for RTYesNo 'No' label.

	// Prompt line used for stdio prompts. For RTAcknowledge, defaults to 'Press
	// Return to continue.' or similar. For RTYesNo, defaults to 'Agree? [Yn]'
	// or similar.
	Prompt string

	// Challenge type unique identifier. This identifies the meaning of the
	// dialog and can be used to respond automatically to known dialogs.
	// Optional.
	UniqueID string

	// Specifies the options for RTSelect.
	Options []Option

	// An implicit challenge will never be shown to the user but may be provided
	// by a response file.
	Implicit bool
}

// An option in an RTSelect challenge.
type Option struct {
	Title string // Option title.
	Value string // Internal value that the option represents.
}

// A user's response to a prompt.
type Response struct {
	Cancelled      bool   // Set this to true if the user cancelled the challenge.
	Value          string // Value the user entered, if applicable.
	Noninteractive bool   // Set to true if the response came from a noninteractive source.
}

// Specifies the initial parameters for a status dialog.
type StatusInfo struct {
	Title      string // Title to be used for the status dialog.
	StatusLine string // The status line. This may contain multiple lines if desired.
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
	// Synchronously present a prompt to the user.
	Prompt(*Challenge) (*Response, error)

	// Asynchronously present status information to the user.
	Status(*StatusInfo) (StatusSink, error)
}
