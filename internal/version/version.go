package version

const Value = "1.5.0"

func ScannerUserAgent() string {
	return "PRS/" + Value + " (defensive security scanner)"
}

func RepeaterUserAgent() string {
	return "PRS-Repeater/" + Value
}

func FuzzerUserAgent() string {
	return "PRS-Fuzzer/" + Value
}
