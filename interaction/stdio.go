package interaction

import "fmt"
import "os"
import "bufio"
import "strings"

func Stdio(c *Challenge) (*Response, error) {
	switch c.ResponseType {
	case RTAcknowledge:
		return stdioAcknowledge(c)
	case RTYesNo:
		return stdioYesNo(c)
	case RTLineString:
		return stdioLineString(c)
	default:
		return nil, fmt.Errorf("unsupported challenge type")
	}
}

func stdioAcknowledge(c *Challenge) (*Response, error) {
	p := c.Prompt
	if p == "" {
		p = "Press Return to continue."
	}

	fmt.Fprintf(os.Stderr, `%s
%s

%s`, titleLine(c.Title), c.Body, p)

	waitReturn()
	return &Response{}, nil
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

	fmt.Fprintf(os.Stderr, `%s
%s

%s `, titleLine(c.Title), c.Body, p)

	v := waitLine()
	return &Response{Value: v}, nil
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
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "y" || s == "yes" || s == "" {
			return true
		} else if s == "n" || s == "no" {
			return false
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
	s := repeat(n) + title
	if len(s) < lineLength {
		s += repeat(lineLength - len(s))
	}
	return s
}
