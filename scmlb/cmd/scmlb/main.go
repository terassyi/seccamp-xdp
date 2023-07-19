package main

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/subcommands/fw"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/subcommands/stat"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
)

var rootCmd = &cobra.Command{
	Use:     "scmlb",
	Short:   "scmlb(security mini camp load balancer) is the toy locad balancer.\n scmlb command is cli to control scmlbd",
	RunE:    rootMain,
	Version: scmlb.Version,
}

// この関数はプログラムの起動時に一度だけ呼び出される関数です。
// ここでは CLI のフラグの値をせっとしたり、サブコマンドを設定しています。
func init() {
	// グローバルなフラグをセットしています
	rootCmd.PersistentFlags().IntVar(&constants.LogLevel, "level", 0, "Log level")
	rootCmd.PersistentFlags().StringVar(&constants.LogOutput, "output", "stdout", "Log output target")
	rootCmd.PersistentFlags().BoolVar(&constants.LogFormat, "json", false, "Json format log")

	rootCmd.PersistentFlags().StringVar(&api.Endpoint, "endpoint", constants.API_SERVER_ENDPOINT, "endpoint for API server")
	rootCmd.PersistentFlags().IntVar(&api.Port, "port", int(constants.API_SERVER_PORT), "endpoint's port for API server")

	// $ scmlb stat で呼び出される stat サブコマンドを登録しています
	rootCmd.AddCommand(&stat.StatCmd)
	// $ scmlb fw で呼び出される fire wall サブコマンドを登録しています
	rootCmd.AddCommand(&fw.FwCmd)
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
