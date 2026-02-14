package interactive

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MOYARU/prs/internal/app/scan"
	"github.com/MOYARU/prs/internal/app/ui"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/spf13/cobra" // cobra import
	"golang.org/x/term"
)

const maxRepeaterBodyBytes = 1 << 20 // 1 MiB

var commonPortServices = map[int]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	465:   "smtps",
	587:   "submission",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1433:  "ms-sql-s",
	1521:  "oracle",
	2049:  "nfs",
	2375:  "docker",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5672:  "amqp",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9200:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

// RunInteractiveMode starts the interactive mode of PRS.
func RunInteractiveMode(cmdObj *cobra.Command) {
	ui.PrintGradientAsciiArt()

	// Print help text (flag descriptions, examples) but remove duplicate ASCII art
	helpText := cmdObj.Long
	helpText = strings.Replace(helpText, ui.AsciiArt, "", 1)
	fmt.Println(helpText)

	fmt.Println()
	fmt.Printf("%s%s%s\n", ui.ColorGray, msges.GetUIMessage("InteractiveWelcome"), ui.ColorReset)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to enter raw mode:", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var cmdBuffer []rune
	var cursorPos int
	history := []string{}
	historyIndex := 0
	readBuf := make([]byte, 1024)

Loop:
	for {
		// Print prompt
		prompt := getPrompt()

		// Calculate visual offset for cursor
		suffix := cmdBuffer[cursorPos:]
		moveBack := 0
		for _, r := range suffix {
			// Simple heuristic for wide characters (CJK, Hangul, etc.)
			if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
				(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
				(r >= 0xac00 && r <= 0xd7a3) ||
				(r >= 0xf900 && r <= 0xfaff) ||
				(r >= 0xfe10 && r <= 0xfe19) ||
				(r >= 0xfe30 && r <= 0xfe6f) ||
				(r >= 0xff00 && r <= 0xff60) ||
				(r >= 0xffe0 && r <= 0xffe6)) {
				moveBack += 2
			} else {
				moveBack += 1
			}
		}

		fmt.Print("\r\033[K" + prompt + string(cmdBuffer))
		if moveBack > 0 {
			fmt.Printf("\033[%dD", moveBack)
		}

		// Read byte
		n, err := os.Stdin.Read(readBuf)
		if err != nil {
			break
		}

		// Handle arrow keys + Escape sequence
		if n >= 3 && readBuf[0] == 27 && readBuf[1] == 91 {
			switch readBuf[2] {
			case 65: // Up Arrow
				if historyIndex > 0 {
					historyIndex--
					cmdBuffer = []rune(history[historyIndex])
					cursorPos = len(cmdBuffer)
				}
			case 66: // Down Arrow
				if historyIndex < len(history)-1 {
					historyIndex++
					cmdBuffer = []rune(history[historyIndex])
					cursorPos = len(cmdBuffer)
				} else {
					historyIndex = len(history)
					cmdBuffer = []rune{}
					cursorPos = 0
				}
			case 68: // Left Arrow
				if cursorPos > 0 {
					cursorPos--
				}
			case 67: // Right Arrow
				if cursorPos < len(cmdBuffer) {
					cursorPos++
				}
			}
			continue
		}

		// Handle other keys
		inputRunes := []rune(string(readBuf[:n]))
		for _, char := range inputRunes {
			switch char {
			case 3: // Ctrl+C
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Println()
				return
			case 13, 10: // Enter
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Println()
				input := strings.TrimSpace(string(cmdBuffer))
				if len(input) > 0 {
					history = append(history, input)
					historyIndex = len(history)
				}
				cmdBuffer = []rune{}
				cursorPos = 0

				// Process command
				if processCommand(input) {
					return // Exit requested
				}
				oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				continue Loop
			case 127, 8: // Backspace
				if cursorPos > 0 {
					cmdBuffer = append(cmdBuffer[:cursorPos-1], cmdBuffer[cursorPos:]...)
					cursorPos--
				}
			default:
				if char >= 32 {
					// Insert at cursor
					cmdBuffer = append(cmdBuffer, 0)
					copy(cmdBuffer[cursorPos+1:], cmdBuffer[cursorPos:])
					cmdBuffer[cursorPos] = char
					cursorPos++
				}
			}
		}
	}
}

func getPrompt() string {
	lang := "KO"
	if msges.CurrentLanguage == msges.LangEN {
		lang = "EN"
	}
	return fmt.Sprintf("%s[%s] > %s", ui.ColorGray, lang, ui.ColorReset)
}

func processCommand(input string) bool {

	// Handle exit commands
	if input == "exit" || input == "quit" {
		fmt.Printf("%s%s%s\n", ui.ColorGray, msges.GetUIMessage("InteractiveExit"), ui.ColorReset)
		return true
	}

	if input == "clear" || input == "cls" {
		fmt.Print("\033[H\033[2J")
		return false
	}

	if input == "help" {
		fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("InteractiveHelp"), ui.ColorReset)
		fmt.Printf("%s  scan <target_url> [--active] [--crawl] [--respect-robots] [--depth N] [--json] [--delay MS]%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  prs <target_url> ...%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  port <host> [start-end]%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  repeater <METHOD> <url> [body]%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  fuzz <url_with_FUZZ> <wordlist_path>%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  help%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  clear / cls%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  exit / quit%s\n", ui.ColorGray, ui.ColorReset)
		return false
	}

	parts := strings.Fields(input)
	if len(parts) == 0 {
		return false
	}

	command := parts[0]
	cmdArgs := parts[1:]

	switch command {
	case "scan", "prs":
		if len(cmdArgs) == 0 {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("InteractiveErrorTarget", command), ui.ColorReset)
			return false
		}

		target := cmdArgs[0]
		active, jsonOut, crawl, respectRobots, depth, delay, err := parseScanFlags(cmdArgs[1:])
		if err != nil {
			fmt.Printf("%s%s%s\n", ui.ColorRed, err, ui.ColorReset)
			return false
		}

		htmlOut, err := ui.Confirm(msges.GetUIMessage("AskSaveHTML"))
		if err != nil {
			fmt.Println()
			return false
		}

		err = scan.RunScan(target, active, crawl, respectRobots, depth, jsonOut, htmlOut, delay)
		if err != nil {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("InteractiveScanFailed", err), ui.ColorReset)
		}
	case "repeater":
		handleRepeater(cmdArgs)
	case "port":
		handlePortScan(cmdArgs)
	case "fuzz":
		handleFuzzer(cmdArgs)
	default:
		fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("InteractiveErrorUnknown", command), ui.ColorReset)
	}
	return false
}

// flag parsing helper
func parseScanFlags(args []string) (bool, bool, bool, bool, int, int, error) {
	active := false
	jsonOut := false
	crawl := false
	respectRobots := false
	depth := 2
	delay := 0

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--active":
			active = true
		case "--json":
			jsonOut = true
		case "--crawl":
			crawl = true
		case "--no-crawl":
			crawl = false
		case "--respect-robots":
			respectRobots = true
		case "--depth":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					depth = d
					i++
				}
			}
		case "--delay":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					delay = d
					i++
				}
			}
		default:
			return false, false, false, false, 0, 0, errors.New(msges.GetUIMessage("InteractiveErrorUnknownFlag", arg))
		}
	}
	return active, jsonOut, crawl, respectRobots, depth, delay, nil
}

func handleRepeater(args []string) {
	if len(args) < 2 {
		fmt.Printf("%sUsage: repeater <METHOD> <URL> [BODY]%s\n", ui.ColorRed, ui.ColorReset)
		return
	}
	method := strings.ToUpper(args[0])
	url := args[1]
	var body io.Reader
	if len(args) > 2 {
		bodyContent := strings.Join(args[2:], " ")
		body = strings.NewReader(bodyContent)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fmt.Printf("%sError creating request: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}

	req.Header.Set("User-Agent", "PRS-Repeater/1.8.0")
	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%sRequest failed: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	fmt.Printf("\n%s[%s] %s %s (%v)%s\n", ui.ColorGreen, method, resp.Status, url, duration, ui.ColorReset)
	for k, v := range resp.Header {
		fmt.Printf("%s%s: %s%s\n", ui.ColorGray, k, strings.Join(v, ", "), ui.ColorReset)
	}
	fmt.Println()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRepeaterBodyBytes+1))
	if err != nil {
		fmt.Printf("%sError reading response body: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}
	if len(bodyBytes) > maxRepeaterBodyBytes {
		bodyBytes = bodyBytes[:maxRepeaterBodyBytes]
		fmt.Printf("%s[Notice] Response body truncated to %d bytes.%s\n", ui.ColorYellow, maxRepeaterBodyBytes, ui.ColorReset)
	}
	fmt.Println(string(bodyBytes))
}

func handleFuzzer(args []string) {
	if len(args) < 2 {
		fmt.Printf("%sUsage: fuzz <URL_WITH_FUZZ> <WORDLIST_PATH>%s\n", ui.ColorRed, ui.ColorReset)
		return
	}
	targetURL := args[0]
	wordlistPath := args[1]

	if !strings.Contains(targetURL, "FUZZ") {
		fmt.Printf("%sError: URL must contain 'FUZZ' placeholder.%s\n", ui.ColorRed, ui.ColorReset)
		return
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("%sError opening wordlist: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}
	defer file.Close()

	fmt.Printf("%sStarting Fuzzer on %s...%s\n", ui.ColorGreen, targetURL, ui.ColorReset)

	client := &http.Client{Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // 20 concurrent requests

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}

		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := strings.ReplaceAll(targetURL, "FUZZ", w)
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "PRS-Fuzzer/1.8.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			color := ui.ColorWhite
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				color = ui.ColorGreen
			} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				color = ui.ColorInfo // Assuming ColorInfo exists (Blue/Cyan)
			} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				color = ui.ColorLow // Assuming ColorLow exists (Yellow/Orange)
			} else if resp.StatusCode >= 500 {
				color = ui.ColorRed
			}

			fmt.Printf("[%s%d%s] %s\n", color, resp.StatusCode, ui.ColorReset, url)
		}(word)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("%sError reading wordlist: %v%s\n", ui.ColorRed, err, ui.ColorReset)
	}
	wg.Wait()
	fmt.Printf("%sFuzzing completed.%s\n", ui.ColorGreen, ui.ColorReset)
}

func handlePortScan(args []string) {
	if len(args) < 1 {
		fmt.Printf("%sUsage: port <HOST> [START-END]%s\n", ui.ColorRed, ui.ColorReset)
		return
	}

	host := strings.TrimSpace(args[0])
	if host == "" {
		fmt.Printf("%sError: host is empty.%s\n", ui.ColorRed, ui.ColorReset)
		return
	}

	startPort, endPort := 1, 1024
	if len(args) >= 2 {
		parts := strings.SplitN(args[1], "-", 2)
		if len(parts) != 2 {
			fmt.Printf("%sError: port range must be START-END (e.g., 1-1024).%s\n", ui.ColorRed, ui.ColorReset)
			return
		}
		s, err1 := strconv.Atoi(parts[0])
		e, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || s < 1 || e > 65535 || s > e {
			fmt.Printf("%sError: invalid port range.%s\n", ui.ColorRed, ui.ColorReset)
			return
		}
		startPort, endPort = s, e
	}

	fmt.Printf("%sScanning ports on %s (%d-%d)...%s\n", ui.ColorGreen, host, startPort, endPort, ui.ColorReset)

	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 200)
	timeout := 500 * time.Millisecond

	for p := startPort; p <= endPort; p++ {
		port := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			openPorts = append(openPorts, port)
			mu.Unlock()
		}()
	}

	wg.Wait()
	sort.Ints(openPorts)

	if len(openPorts) == 0 {
		fmt.Printf("%sNo open ports found.%s\n", ui.ColorYellow, ui.ColorReset)
		return
	}

	fmt.Printf("%sOpen ports (%d):%s\n", ui.ColorGreen, len(openPorts), ui.ColorReset)
	for _, p := range openPorts {
		if svc, ok := commonPortServices[p]; ok {
			fmt.Printf(" - %d/tcp (%s)\n", p, svc)
		} else {
			fmt.Printf(" - %d/tcp\n", p)
		}
	}
}
