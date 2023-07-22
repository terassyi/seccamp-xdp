package dosprotection

import "github.com/spf13/cobra"

var DoSProtectionCmd = cobra.Command{
	Use:   "dos-protection",
	Short: "DoS protection policy subcommands",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	DoSProtectionCmd.AddCommand(&setCmd)
	DoSProtectionCmd.AddCommand(&getCmd)
	DoSProtectionCmd.AddCommand(&deleteCmd)
}
