package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var treeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Display the full command tree",
	Long:  "Display the command and subcommand tree. Use --flags to include local flag details and --inherited to include inherited flag details.",
	Args:  cobra.NoArgs,
	RunE:  runTree,
}

var (
	treeIncludeFlags     bool
	treeIncludeInherited bool
)

type printCommandTreeInput struct {
	cmd    *cobra.Command
	prefix string
}

type commandTreeJSON struct {
	Name           string            `json:"name"`
	Short          string            `json:"short"`
	LocalFlags     []string          `json:"local_flags,omitempty"`
	InheritedFlags []string          `json:"inherited_flags,omitempty"`
	Subcommands    []commandTreeJSON `json:"subcommands,omitempty"`
}

func init() {
	treeCmd.Flags().BoolVar(&treeIncludeFlags, "flags", false, "Include local flags in text tree output")
	treeCmd.Flags().BoolVar(&treeIncludeInherited, "inherited", false, "Include inherited flags in text tree output")
	rootCmd.AddCommand(treeCmd)
}

func runTree(_ *cobra.Command, _ []string) error {
	initTreeSurface(rootCmd)

	if jsonOutput {
		data, err := json.MarshalIndent(buildCommandTreeJSON(rootCmd), "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

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
// box-drawing connectors. Flag details are opt-in so the default tree stays
// focused on the command surface.
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

	total := len(visible)
	if treeIncludeFlags {
		total += len(localFlags)
	}
	if treeIncludeInherited && len(inheritedFlags) > 0 {
		total++
	}
	idx := 0

	// Print local flags.
	if treeIncludeFlags {
		for _, flag := range localFlags {
			idx++
			connector := "├── "
			if idx == total {
				connector = "└── "
			}
			fmt.Fprintf(b, "%s%s%s\n", prefix, connector, flag)
		}
	}

	if treeIncludeInherited && len(inheritedFlags) > 0 {
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

func buildCommandTreeJSON(cmd *cobra.Command) commandTreeJSON {
	node := commandTreeJSON{
		Name:           cmd.Name(),
		Short:          cmd.Short,
		LocalFlags:     visibleFlagNames(cmd.LocalFlags()),
		InheritedFlags: visibleFlagNames(cmd.InheritedFlags()),
	}
	for _, child := range cmd.Commands() {
		if child.Hidden {
			continue
		}
		node.Subcommands = append(node.Subcommands, buildCommandTreeJSON(child))
	}
	return node
}
