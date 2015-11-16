package interaction

import "os"
import "os/exec"
import "fmt"
import "io/ioutil"
import "syscall"

func Dialog(c *Challenge) (*Response, error) {
	cmdName, cmdType := findDialogCommand()
	if cmdName == "" {
		return nil, fmt.Errorf("cannot find whiptail or dialog binary in path")
	}

	width := "78"
	height := "45"
	yesLabelArg := "--yes-label"
	noLabelArg := "--no-label"
	noTagsArg := "--no-tags"
	if cmdType == "whiptail" {
		yesLabelArg = "--yes-button"
		noLabelArg = "--no-button"
		noTagsArg = "--notags"
	}

	var opts []string
	if c.Title != "" {
		opts = append(opts, "--backtitle", "ACME", "--title", c.Title)
	}

	var err error
	var pipeR *os.File
	var pipeW *os.File

	switch c.ResponseType {
	case RTAcknowledge:
		opts = append(opts, "--msgbox", c.Body, height, width)
	case RTYesNo:
		yesLabel := c.YesLabel
		if yesLabel == "" {
			yesLabel = "Yes"
		}
		noLabel := c.NoLabel
		if noLabel == "" {
			noLabel = "No"
		}
		opts = append(opts, yesLabelArg, yesLabel, noLabelArg, noLabel, "--yesno", c.Body, height, width)
	case RTLineString:
		pipeR, pipeW, err = os.Pipe()
		if err != nil {
			return nil, err
		}

		defer pipeR.Close()
		defer pipeW.Close()
		opts = append(opts, "--output-fd", "3", "--inputbox", c.Body, height, width)
	case RTSelect:
		pipeR, pipeW, err = os.Pipe()
		if err != nil {
			return nil, err
		}

		defer pipeR.Close()
		defer pipeW.Close()
		opts = append(opts, "--output-fd", "3", noTagsArg, "--menu", c.Body, height, width, "5")
		for _, o := range c.Options {
			opts = append(opts, o.Value, o.Title)
		}
	}

	cmd := exec.Command(cmdName, opts...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if pipeW != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, pipeW)
	}

	rc, xerr, err := runCommand(cmd)
	if err != nil {
		return nil, err
	}

	res := &Response{}
	if pipeW != nil {
		pipeW.Close()
	}

	switch c.ResponseType {
	case RTLineString, RTSelect:
		b, err := ioutil.ReadAll(pipeR)
		if err != nil {
			return nil, err
		}

		res.Value = string(b)
		fallthrough
	case RTYesNo, RTAcknowledge:
		if rc != 0 && rc != 1 {
			return nil, xerr
		}
		res.Cancelled = (rc == 1)
	}

	return res, nil
}

var dialogCommand = ""
var dialogCommandType = ""

func findDialogCommand() (string, string) {
	if dialogCommand != "" {
		return dialogCommand, dialogCommandType
	}

	for _, s := range []string{"whiptail", "dialog"} {
		p, err := exec.LookPath(s)
		if err == nil {
			dialogCommand = p
			dialogCommandType = s
			return dialogCommand, dialogCommandType
		}
	}

	return "", ""
}

func runCommand(cmd *exec.Cmd) (int, error, error) {
	err := cmd.Run()
	if err == nil {
		return 0, nil, nil
	}

	if e, ok := err.(*exec.ExitError); ok {
		if ws, ok := e.Sys().(syscall.WaitStatus); ok {
			return ws.ExitStatus(), err, nil
		}
	}

	return 255, err, err
}
