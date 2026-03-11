package main

import (
	"fmt"
	"slices"
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

type printCommandTreeInput struct {
	cmd    *cobra.Command
	prefix string
}

func init() {
	rootCmd.AddCommand(treeCmd)
}

func runTree(_ *cobra.Command, _ []string) error {
	initTreeSurface(rootCmd)

	var b strings.Builder
	printCommandTree(&b, printCommandTreeInput{cmd: rootCmd})
	fmt.Print(b.String())
	return nil
}

func initTreeSurface(cmd *cobra.Command) {
	cmd.InitDefaultHelpFlag()
	if cmd == rootCmd {
		cmd.InitDefaultHelpCmd()
		cmd.InitDefaultVersionFlag()
		cmd.InitDefaultCompletionCmd()
	}
	for _, child := range cmd.Commands() {
		initTreeSurface(child)
	}
}

// printCommandTree recursively prints a command and its children with
// box-drawing connectors. Each command shows its flags indented beneath it.
func printCommandTree(b *strings.Builder, in printCommandTreeInput) {
	cmd := in.cmd
	prefix := in.prefix

	// Print this command's name and short description.
	if cmd == rootCmd {
		fmt.Fprintf(b, "%s — %s\n", cmd.Name(), cmd.Short)
	}

	localFlags := visibleFlagNames(cmd.LocalFlags())
	inheritedFlags := visibleFlagNames(cmd.InheritedFlags())

	// Collect non-hidden subcommands.
	var visible []*cobra.Command
	for _, child := range cmd.Commands() {
		if !child.Hidden {
			visible = append(visible, child)
		}
	}

	total := len(localFlags) + len(visible)
	if len(inheritedFlags) > 0 {
		total++
	}
	idx := 0

	// Print local flags.
	for _, flag := range localFlags {
		idx++
		connector := "├── "
		if idx == total {
			connector = "└── "
		}
		fmt.Fprintf(b, "%s%s%s\n", prefix, connector, flag)
	}

	if len(inheritedFlags) > 0 {
		idx++
		connector := "├── "
		if idx == total {
			connector = "└── "
		}
		fmt.Fprintf(b, "%s%sinherits: %s\n", prefix, connector, strings.Join(inheritedFlags, ", "))
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
		printCommandTree(b, printCommandTreeInput{
			cmd:    child,
			prefix: childPrefix,
		})
	}
}

func visibleFlagNames(flags *pflag.FlagSet) []string {
	var names []string
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		names = append(names, "--"+f.Name)
	})
	slices.Sort(names)
	return names
}
