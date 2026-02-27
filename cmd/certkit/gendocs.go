//go:build gendocs

package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// markerCommandMap maps marker names to the commands whose flags they represent.
// Order determines the table rendering order within the README.
var markerCommandMap = []struct {
	marker string
	cmd    *cobra.Command
	// persistent selects PersistentFlags() instead of Flags().
	persistent bool
}{
	{"global", rootCmd, true},
	{"inspect", inspectCmd, false},
	{"verify", verifyCmd, false},
	{"connect", connectCmd, false},
	{"bundle", bundleCmd, false},
	{"convert", convertCmd, false},
	{"sign-self-signed", signSelfSignedCmd, false},
	{"sign-csr", signCSRCmd, false},
	{"scan", scanCmd, false},
	{"keygen", keygenCmd, false},
	{"csr", csrCmd, false},
	{"ocsp", ocspCmd, false},
	{"crl", crlCmd, false},
}

func main() {
	// Build the full command tree so all flags are registered.
	rootCmd.Version = "dev"

	readmePath := "README.md"
	if len(os.Args) > 1 {
		readmePath = os.Args[1]
	}

	content, err := os.ReadFile(readmePath)
	if err != nil {
		slog.Error("reading README", "path", readmePath, "err", err)
		os.Exit(1)
	}

	original := string(content)
	result := original

	for _, entry := range markerCommandMap {
		table := generateFlagTable(entry.cmd, entry.persistent)
		var spliceErr error
		result, spliceErr = spliceMarker(spliceMarkerInput{
			doc:         result,
			name:        entry.marker,
			replacement: table,
		})
		if spliceErr != nil {
			slog.Error("splicing marker", "marker", entry.marker, "err", spliceErr)
			os.Exit(1)
		}
	}

	if result != original {
		if err := os.WriteFile(readmePath, []byte(result), 0644); err != nil {
			slog.Error("writing README", "path", readmePath, "err", err)
			os.Exit(1)
		}
		slog.Info("updated README", "path", readmePath)
	} else {
		fmt.Fprintf(os.Stderr, "%s is up to date\n", readmePath)
	}
}

// generateFlagTable produces a markdown table for the given command's flags.
func generateFlagTable(cmd *cobra.Command, persistent bool) string {
	var flags *pflag.FlagSet
	if persistent {
		flags = cmd.PersistentFlags()
	} else {
		flags = cmd.Flags()
	}

	type flagRow struct {
		name        string
		defVal      string
		description string
	}

	var rows []flagRow
	flags.VisitAll(func(f *pflag.Flag) {
		// Skip inherited persistent flags when rendering local flags.
		if !persistent && cmd.InheritedFlags().Lookup(f.Name) != nil {
			return
		}
		// Skip internal cobra flags.
		if f.Hidden {
			return
		}

		name := "`--" + f.Name + "`"
		if f.Shorthand != "" {
			name += ", `-" + f.Shorthand + "`"
		}

		defVal := formatDefault(cmd, f)
		rows = append(rows, flagRow{name: name, defVal: defVal, description: f.Usage})
	})

	if len(rows) == 0 {
		return ""
	}

	// Compute column widths.
	flagW, defW, descW := len("Flag"), len("Default"), len("Description")
	for _, r := range rows {
		flagW = max(flagW, len(r.name))
		defW = max(defW, len(r.defVal))
		descW = max(descW, len(r.description))
	}

	var b strings.Builder
	// Header.
	fmt.Fprintf(&b, "| %-*s | %-*s | %-*s |\n", flagW, "Flag", defW, "Default", descW, "Description")
	// Separator.
	fmt.Fprintf(&b, "| %s | %s | %s |\n", strings.Repeat("-", flagW), strings.Repeat("-", defW), strings.Repeat("-", descW))
	// Rows.
	for _, r := range rows {
		fmt.Fprintf(&b, "| %-*s | %-*s | %-*s |\n", flagW, r.name, defW, r.defVal, descW, r.description)
	}

	return b.String()
}

// formatDefault returns the display string for a flag's default value.
// It checks for a readme_default annotation first, then falls back to the
// Cobra default value.
func formatDefault(cmd *cobra.Command, f *pflag.Flag) string {
	// Check for custom readme_default annotation.
	if ann, ok := f.Annotations["readme_default"]; ok && len(ann) > 0 {
		return ann[0]
	}

	// Required flags show _(required)_.
	if isRequired(cmd, f.Name) {
		return "_(required)_"
	}

	switch f.DefValue {
	case "":
		return ""
	case "[]":
		return ""
	case "false":
		return "`false`"
	case "true":
		return "`true`"
	default:
		return "`" + f.DefValue + "`"
	}
}

// isRequired checks whether a flag has been marked as required.
func isRequired(cmd *cobra.Command, flagName string) bool {
	f := cmd.Flags().Lookup(flagName)
	if f == nil {
		return false
	}
	if vals, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; ok {
		for _, v := range vals {
			if v == "true" {
				return true
			}
		}
	}
	return false
}

// spliceMarkerInput holds parameters for spliceMarker.
type spliceMarkerInput struct {
	doc         string
	name        string
	replacement string
}

// spliceMarker replaces content between <!-- certkit:flags:NAME --> and
// <!-- /certkit:flags --> markers with the given replacement text.
func spliceMarker(in spliceMarkerInput) (string, error) {
	openTag := "<!-- certkit:flags:" + in.name + " -->"
	closeTag := "<!-- /certkit:flags -->"

	openIdx := strings.Index(in.doc, openTag)
	if openIdx < 0 {
		return "", fmt.Errorf("missing open marker %q in README.md", openTag)
	}

	// Find the close tag after the open tag.
	afterOpen := openIdx + len(openTag)
	closeIdx := strings.Index(in.doc[afterOpen:], closeTag)
	if closeIdx < 0 {
		return "", fmt.Errorf("missing close marker %q after %q in README.md", closeTag, openTag)
	}
	closeIdx += afterOpen

	// Build the spliced document.
	var b strings.Builder
	b.WriteString(in.doc[:afterOpen])
	b.WriteByte('\n')
	b.WriteString(in.replacement)
	b.WriteString(in.doc[closeIdx:])

	return b.String(), nil
}
