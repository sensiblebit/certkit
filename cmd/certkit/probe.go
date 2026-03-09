package main

import "github.com/spf13/cobra"

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe network services",
}
