package main

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb"
)

var rootCmd = &cobra.Command{
	Use:     "scmlbd",
	Short:   "scmlb(security mini camp load balancer) is the toy locad balancer.\n scmlbd is daemon program.",
	RunE:    rootMain,
	Version: scmlb.Version,
}

func main() {
	execute()
}

func rootMain(cmd *cobra.Command, args []string) error {
	return nil
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
