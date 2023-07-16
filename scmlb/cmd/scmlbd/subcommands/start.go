package subcommands

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/daemon"
)

// この関数はプログラムの起動時に一度だけ呼び出されます
func init() {
	// start サブコマンド用のフラグを定義しています
	StartCmd.Flags().StringP("api-addr", "a", constants.API_SERVER_ENDPOINT, "API server serving address")
	StartCmd.Flags().Int32P("api-port", "p", constants.API_SERVER_PORT, "API server serving port")
	StartCmd.Flags().StringP("upstream", "u", "eth0", "upstream interface")
}

// start サブコマンドの実体
var StartCmd = cobra.Command{
	Use:   "start",
	Short: "start scmlb daemon",
	// start サブコマンドのエントリーポイントの関数です
	RunE: func(cmd *cobra.Command, args []string) error {
		apiAddr, err := cmd.Flags().GetString("api-addr")
		if err != nil {
			log.Fatal(err)
		}
		apiPort, err := cmd.Flags().GetInt32("api-port")
		if err != nil {
			log.Fatal(err)
		}
		upstream, err := cmd.Flags().GetString("upstream")
		if err != nil {
			log.Fatal(err)
		}

		daemon, err := daemon.New(apiAddr, apiPort, upstream)
		if err != nil {
			log.Fatal(err)
		}
		// daemon のループを開始
		return daemon.Run()
	},
}
