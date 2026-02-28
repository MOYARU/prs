package ui

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func SelectLanguage() {
}

// WaitForCancel returns a context that is canceled on Ctrl+C
func WaitForCancel(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// Confirm prompts the user for a yes/no answer.
func Confirm(prompt string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print(prompt + " (y/n): ")
		var input string
		fmt.Scanln(&input)
		return strings.ToLower(input) == "y", nil
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Print(prompt + " (y/n): ")

	for {
		b := make([]byte, 1)
		_, err := os.Stdin.Read(b)
		if err != nil {
			return false, err
		}

		if b[0] == 3 { // Ctrl+C
			fmt.Print("^C\r\n")
			return false, fmt.Errorf("cancelled")
		}

		char := strings.ToLower(string(b[0]))
		if char == "y" {
			fmt.Print("y\r\n")
			return true, nil
		}
		if char == "n" {
			fmt.Print("n\r\n")
			return false, nil
		}
	}
}
