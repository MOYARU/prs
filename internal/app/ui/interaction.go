package ui

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	msges "github.com/MOYARU/prs/internal/messages"
	"golang.org/x/term"
)

func SelectLanguage() {
	// Check if terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("Not a terminal, defaulting to English.")
		return
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to enter raw mode, defaulting to English.")
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	options := []struct {
		Label string
		Lang  msges.Language
	}{
		{"English", msges.LangEN},
		{"Korean (KO)", msges.LangKO},
	}
	selected := 0

	// Initial render
	renderMenu(options, selected)

	for {
		b := make([]byte, 3)
		n, err := os.Stdin.Read(b)
		if err != nil {
			break
		}

		if n == 1 && b[0] == 3 { // Ctrl+C
			term.Restore(int(os.Stdin.Fd()), oldState)
			os.Exit(0)
		}

		if n == 1 && (b[0] == 13 || b[0] == 10) { // Enter (CR or LF)
			msges.SetLanguage(options[selected].Lang)
			term.Restore(int(os.Stdin.Fd()), oldState)
			fmt.Printf("\nSelected: %s\n", options[selected].Label)
			return
		}

		if n == 3 && b[0] == 27 && b[1] == 91 { // Escape sequence
			if b[2] == 65 || b[2] == 68 { // Up or Left
				selected--
				if selected < 0 {
					selected = len(options) - 1
				}
			} else if b[2] == 66 || b[2] == 67 { // Down or Right
				selected++
				if selected >= len(options) {
					selected = 0
				}
			}
			renderMenu(options, selected)
		}
	}
}

func renderMenu(options []struct {
	Label string
	Lang  msges.Language
}, selected int) {
	fmt.Print("\r\033[K") // Clear current line
	fmt.Print("Select Language (Use Arrow Keys & Enter): ")
	for i, opt := range options {
		if i == selected {
			fmt.Printf("[%s] ", opt.Label)
		} else {
			fmt.Printf(" %s  ", opt.Label)
		}
	}
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
