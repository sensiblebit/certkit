package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var treeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Display the full command tree",
	Long:  "Display every command, subcommand, and flag in a tree layout.",
	Args:  cobra.NoArgs,
	RunE:  runTree,
}

func init() {
	rootCmd.AddCommand(treeCmd)
}

func runTree(_ *cobra.Command, _ []string) error {
	// Trigger Cobra's lazy flag registration so --help and --version appear.
	rootCmd.InitDefaultHelpFlag()
	rootCmd.InitDefaultVersionFlag()

	var b strings.Builder
	printCommandTree(&b, rootCmd, "")
	fmt.Print(b.String())
	return nil
}

// printCommandTree recursively prints a command and its children with
// box-drawing connectors. Each command shows its flags indented beneath it.
func printCommandTree(b *strings.Builder, cmd *cobra.Command, prefix string) {
	// Print this command's name and short description.
	if cmd == rootCmd {
		fmt.Fprintf(b, "%s — %s\n", cmd.Name(), cmd.Short)
	}

	// Collect local (non-inherited, non-hidden) flags.
	var flags []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		if cmd.InheritedFlags().Lookup(f.Name) != nil {
			return
		}
		name := "--" + f.Name
		if f.Shorthand != "" {
			name = "-" + f.Shorthand + ", " + name
		}
		flags = append(flags, name)
	})

	// Collect non-hidden subcommands.
	var visible []*cobra.Command
	for _, child := range cmd.Commands() {
		if !child.Hidden {
			visible = append(visible, child)
		}
	}

	total := len(flags) + len(visible)
	idx := 0

	// Print flags.
	for _, flag := range flags {
		idx++
		connector := "├── "
		if idx == total {
			connector = "└── "
		}
		fmt.Fprintf(b, "%s%s%s\n", prefix, connector, flag)
	}

	// Print subcommands.
	for i, child := range visible {
		idx++
		connector := "├── "
		childPrefix := prefix + "│   "
		if i == len(visible)-1 && idx == total {
			connector = "└── "
			childPrefix = prefix + "    "
		}
		fmt.Fprintf(b, "%s%s%s — %s\n", prefix, connector, child.Name(), child.Short)
		printCommandTree(b, child, childPrefix)
	}
}
