package main

import "github.com/spf13/cobra"

// registerCompletion registers a shell completion function for a flag on a
// command. It panics if the flag does not exist (programmer error).
func registerCompletion(cmd *cobra.Command, flagName string, f func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) {
	if err := cmd.RegisterFlagCompletionFunc(flagName, f); err != nil {
		panic(err)
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
