package conntrack

import "github.com/spf13/cobra"

var ConntrackCmd = cobra.Command{
	Use:   "conntrack",
	Short: "conneection tracking related commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	ConntrackCmd.AddCommand(&getCmd)
}
