package interaction

import (
	"bufio"
	"fmt"
	"github.com/hlandau/goutils/text"
	"github.com/mitchellh/go-wordwrap"
	"gopkg.in/cheggaaa/pb.v1"
	"os"
	"strconv"
	"strings"
	"sync"
)

type stdioInteractor struct{}

// Interactor which uses un-fancy stdio prompts.
var Stdio Interactor = stdioInteractor{}

type stdioStatusSink struct {
	closeChan  chan struct{}
	closeOnce  sync.Once
	closedChan chan struct{}
	updateChan chan struct{}
	infoMutex  sync.Mutex
	statusLine string
	progress   int
}

func (ss *stdioStatusSink) Close() error {
	ss.closeOnce.Do(func() {
		close(ss.closeChan)
	})
	<-ss.closedChan
	return nil
}

func (ss *stdioStatusSink) SetProgress(n, ofM int) {
	ss.infoMutex.Lock()
	defer ss.infoMutex.Unlock()
	ss.progress = int((float64(n) / float64(ofM)) * 100)
	ss.notify()
}

func (ss *stdioStatusSink) SetStatusLine(status string) {
	ss.infoMutex.Lock()
	defer ss.infoMutex.Unlock()
	ss.statusLine = status
	ss.notify()
}

func (ss *stdioStatusSink) notify() {
	select {
	case ss.updateChan <- struct{}{}:
	default:
	}
}

func (ss *stdioStatusSink) loop() {
	bar := pb.StartNew(100)
	bar.ShowSpeed = false
	bar.ShowCounters = false
	bar.ShowTimeLeft = false
	bar.SetMaxWidth(lineLength)

A:
	for {
		select {
		case <-ss.closeChan:
			break A
		case <-ss.updateChan:
			ss.infoMutex.Lock()
			statusLine := ss.statusLine
			idx := strings.IndexByte(statusLine, '\n')
			if idx >= 0 {
				statusLine = statusLine[0:idx]
			}
			progress := ss.progress
			ss.infoMutex.Unlock()

			bar.Set(progress)
			bar.Postfix("  " + statusLine)
		}
	}

	//bar.Update()
	bar.Finish()
	close(ss.closedChan)
}

func (stdioInteractor) Status(c *StatusInfo) (StatusSink, error) {
	ss := &stdioStatusSink{
		closeChan:  make(chan struct{}),
		closedChan: make(chan struct{}),
		updateChan: make(chan struct{}, 10),
		statusLine: c.StatusLine,
	}

	ss.updateChan <- struct{}{}
	go ss.loop()
	return ss, nil
}

func (stdioInteractor) Prompt(c *Challenge) (*Response, error) {
	switch c.ResponseType {
	case RTAcknowledge:
		return stdioAcknowledge(c)
	case RTYesNo:
		return stdioYesNo(c)
	case RTLineString:
		return stdioLineString(c)
	case RTSelect:
		return stdioSelect(c)
	default:
		return nil, fmt.Errorf("unsupported challenge type")
	}
}

func stdioAcknowledge(c *Challenge) (*Response, error) {
	p := c.Prompt
	if p == "" {
		p = "Press Return to continue."
	}

	PrintStderrMessage(c.Title, fmt.Sprintf("%s\n\n%s", c.Body, p))

	waitReturn()
	return &Response{}, nil
}

func PrintStderrMessage(title, body string) {
	fmt.Fprintf(os.Stderr, "%s\n%s\n", titleLine(title), wordwrap.WrapString(body, lineLength))
}

func stdioYesNo(c *Challenge) (*Response, error) {
	p := c.Prompt
	if p == "" {
		p = "Continue?"
	}

	fmt.Fprintf(os.Stderr, `%s
%s

`, titleLine(c.Title), c.Body)

	yes := waitYN(p)
	return &Response{Cancelled: !yes}, nil
}

func stdioLineString(c *Challenge) (*Response, error) {
	p := c.Prompt
	if p == "" {
		p = ">"
	}

	PrintStderrMessage(c.Title, fmt.Sprintf("%s\n\n%s", c.Body, p))

	v := waitLine()
	return &Response{Value: v}, nil
}

func stdioSelect(c *Challenge) (*Response, error) {

	p := c.Prompt
	if p == "" {
		p = ">"
	}

	PrintStderrMessage(c.Title, fmt.Sprintf("%s\n\n", c.Body))

	for i, o := range c.Options {
		t := o.Title
		if t == "" {
			t = o.Value
		}
		fmt.Fprintf(os.Stderr, "  %v) %s\n", i+1, t)
	}

	fmt.Fprintf(os.Stderr, "%s ", p)
	v := strings.TrimSpace(waitLine())
	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil || n == 0 || int(n-1) >= len(c.Options) {
		return stdioSelect(c)
	}

	return &Response{Value: c.Options[int(n-1)].Value}, nil
}

func waitReturn() {
	waitLine()
}

func waitLine() string {
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(s, "\r\n")
}

func waitYN(prompt string) bool {
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "%s [Yn] ", prompt)
		s, _ := r.ReadString('\n')
		if v, ok := text.ParseBoolUserDefaultYes(s); ok {
			return v
		}
	}
}

const lineLength = 70

func repeat(n int) string {
	return "--------------------------------------------------------------------------------"[80-n:]
}

func titleLine(title string) string {
	if title != "" {
		title = " " + title + " "
	}

	n := lineLength/2 - len(title)/2
	s := "\n\n" + repeat(n) + title
	if len(s) < lineLength {
		s += repeat(lineLength - len(s))
	}
	return s
}
