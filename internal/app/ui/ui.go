package ui

import (
	"fmt"
	"strings"
)

const AsciiArt = `
██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝
██████╔╝██████╔╝███████╗
██╔═══╝ ██╔══██╗╚════██║
██║     ██║  ██║███████║
╚═╝     ╚═╝  ╚═╝╚══════╝
`

const (
	ColorReset  = "\033[0m"
	ColorGray   = "\033[90m" // Light gray
	ColorWhite  = "\033[97m" // White
	ColorRed    = "\033[91m" // Bright Red
	ColorGreen  = "\033[92m" // Bright Green
	ColorYellow = "\033[93m" // Bright Yellow

	ColorInfo   = "\033[37m" // White/Light Gray for INFO
	ColorLow    = "\033[34m" // Blue for LOW
	ColorMedium = "\033[33m" // Yellow/Orange for MEDIUM
	ColorHigh   = "\033[31m" // Red for HIGH
)

// PrintGradientAsciiArt prints the ASCII art with a Yellow to Blue gradient.
func PrintGradientAsciiArt() {
	// Preserve left padding for visual alignment.
	lines := strings.Split(strings.Trim(AsciiArt, "\n"), "\n")
	for i, line := range lines {
		ratio := float64(i) / float64(len(lines)-1)

		var r, g, b int
		// Yellow (255,255,0) -> Cyan (0,255,255) -> Blue (0,0,255)
		if ratio < 0.5 {
			localRatio := ratio * 2
			r = int(255 * (1 - localRatio))
			g = 255
			b = int(255 * localRatio)
		} else {
			localRatio := (ratio - 0.5) * 2
			r = 0
			g = int(255 * (1 - localRatio))
			b = 255
		}

		fmt.Printf("\033[38;2;%d;%d;%dm%s\033[0m\n", r, g, b, line)
	}
}
