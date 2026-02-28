/*
Copyright (c) 2026 moyaru <rbffo@icloud.com>
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/MOYARU/prs/internal/app/interactive"
	"github.com/MOYARU/prs/internal/app/scan"
	"github.com/MOYARU/prs/internal/app/ui"
	appver "github.com/MOYARU/prs/internal/version"
	"github.com/spf13/cobra"
)

var (
	version = appver.Value

	activeScan    bool
	jsonOutput    bool
	htmlOutput    bool
	respectRobots bool
	depth         int
	delay         int
)

var rootCmd = &cobra.Command{
	Use:   "prs [target]",
	Short: "PRS is a defensive-first web security scanner that identifies common vulnerabilities and misconfigurations including network, TLS, HTTP, security headers, authentication, session, file exposure, input handling, access control, and client-side security issues, without direct exploitation.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			interactive.RunInteractiveMode(cmd)
		} else {
			target := args[0]
			err := scan.RunScan(target, activeScan, true, respectRobots, depth, jsonOutput, htmlOutput, delay, false)
			if err != nil {
				fmt.Printf("%sScan failed: %v%s\n", ui.ColorRed, err, ui.ColorReset)
				os.Exit(1)
			}
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
func init() {
	rootCmd.Version = version

	rootCmd.Flags().BoolVar(&activeScan, "active", false, "Enable active scan (disabled by default)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output result as JSON")
	rootCmd.Flags().BoolVar(&htmlOutput, "html", false, "Output result as HTML")
	rootCmd.Flags().BoolVar(&respectRobots, "respect-robots", false, "Respect robots.txt disallow rules during crawling")
	rootCmd.Flags().IntVar(&depth, "depth", 2, "Crawling depth (default: 2)")
	rootCmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests in milliseconds (e.g., 500)")

	rootCmd.Long = ui.AsciiArt + `
PRS is a lightweight, defensive-first web security scanner.

Usage:
   prs [target_url] [flags]

Example:
  prs https://example.com
  prs https://example.com --depth 3
  prs https://example.com --active

  port 127.0.0.1
  port 127.0.0.1 1-10000

Flags:
  --active             Enable active scan (disabled by default)
  --respect-robots     Respect robots.txt disallow rules during crawling
  --depth              Crawling depth (default: 2)
  --json               Output result as JSON
  --html               Output result as HTML
  --delay              Delay between requests in milliseconds

This tool is intended for ethical hacking and security testing on assets you own or have explicit permission to test.
`
}
