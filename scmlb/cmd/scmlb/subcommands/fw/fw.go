package fw

import "github.com/spf13/cobra"

var FwCmd = cobra.Command{
	Use:   "fw",
	Short: "manage a fire wall function",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	FwCmd.AddCommand(&setCmd)
	FwCmd.AddCommand(&getCmd)
	FwCmd.AddCommand(&deleteCmd)
}
