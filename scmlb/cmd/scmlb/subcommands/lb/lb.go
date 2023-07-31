package lb

import (
	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/subcommands/lb/conntrack"
)

var LbCmd = cobra.Command{
	Use:   "lb",
	Short: "lb related command",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	LbCmd.AddCommand(&SetCmd)
	LbCmd.AddCommand(&getCmd)
	LbCmd.AddCommand(&deleteCmd)
	LbCmd.AddCommand(&drainCmd)

	LbCmd.AddCommand(&conntrack.ConntrackCmd)
}
