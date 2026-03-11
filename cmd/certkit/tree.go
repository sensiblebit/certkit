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

	// Collect every visible flag the command accepts, including inherited ones.
	var flags []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		flags = append(flags, "--"+f.Name)
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
		printCommandTree(b, printCommandTreeInput{
			cmd:    child,
			prefix: childPrefix,
		})
	}
}
