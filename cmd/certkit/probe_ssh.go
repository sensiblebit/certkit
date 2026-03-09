package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/spf13/cobra"
)

var (
	probeSSHFormat   string
	probeSSHFIPS1402 bool
	probeSSHFIPS1403 bool
)

const probeSSHDefaultTimeout = 10 * time.Second

var probeSSHCmd = &cobra.Command{
	Use:   "ssh <host[:port]>",
	Short: "Probe SSH transport algorithms without authenticating",
	Long: `Probe an SSH server, capture its banner, and display the transport
algorithms it advertises in the initial key exchange.

Port defaults to 22 if not specified.`,
	Example: `  certkit probe ssh example.com
  certkit probe ssh example.com:2222
  certkit --json probe ssh example.com
  certkit probe ssh example.com --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runProbeSSH,
}

func init() {
	probeCmd.AddCommand(probeSSHCmd)
	probeSSHCmd.Flags().StringVar(&probeSSHFormat, "format", "text", "Output format: text, json")
	probeSSHCmd.Flags().BoolVar(&probeSSHFIPS1402, "fips-140-2", false, "Apply conservative FIPS 140-2 heuristic checks to advertised SSH algorithms")
	probeSSHCmd.Flags().BoolVar(&probeSSHFIPS1403, "fips-140-3", false, "Apply conservative FIPS 140-3 heuristic checks to advertised SSH algorithms")

	registerCompletion(probeSSHCmd, completionInput{"format", fixedCompletion("text", "json")})
}

func runProbeSSH(cmd *cobra.Command, args []string) error {
	host, port, err := parseHostPortWithDefault(args[0], "22")
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", args[0], err)
	}
	policy, err := selectedPolicy(probeSSHFIPS1402, probeSSHFIPS1403)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, probeSSHDefaultTimeout)
	}
	defer cancel()

	result, err := certkit.ProbeSSH(ctx, certkit.SSHProbeInput{
		Host:   host,
		Port:   port,
		Policy: policy,
	})
	if err != nil {
		return fmt.Errorf("probing SSH server %s: %w", args[0], err)
	}

	format := probeSSHFormat
	if jsonOutput {
		format = "json"
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	case "text":
		fmt.Print(certkit.FormatSSHProbeResult(result))
		return nil
	default:
		return fmt.Errorf("%w %q (use text or json)", ErrUnsupportedOutputFormat, format)
	}
}
