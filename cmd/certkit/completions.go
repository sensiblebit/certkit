package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// completionInput holds the parameters for registering a shell completion
// function on a command flag.
type completionInput struct {
	flagName     string
	completeFunc func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)
}

// registerCompletion registers a shell completion function for a flag on a
// command. It panics if the flag does not exist (programmer error).
func registerCompletion(cmd *cobra.Command, in completionInput) {
	if err := cmd.RegisterFlagCompletionFunc(in.flagName, in.completeFunc); err != nil {
		panic(fmt.Sprintf("%s --%s: %v", cmd.Name(), in.flagName, err))
	}
}

// fixedCompletion returns a shell completion function that suggests the given
// values with no file completion fallback.
func fixedCompletion(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// directoryCompletion is a shell completion function that suggests only
// directories (no regular files).
func directoryCompletion(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveFilterDirs
}

// fileCompletion is a shell completion function that suggests files using the
// shell's default file completion behavior.
func fileCompletion(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveDefault
}
