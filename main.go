/*
Copyright (c) 2026 moyaru <rbffo@icloud.com>
*/

package main

import (
	"github.com/MOYARU/prs/cmd"
	"github.com/MOYARU/prs/internal/app/ui"
)

func main() {
	ui.SelectLanguage()
	cmd.Execute()
}
