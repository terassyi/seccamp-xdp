package main

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlbd/subcommands"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
)

var rootCmd = &cobra.Command{
	Use:     "scmlbd",
	Short:   "scmlb(security mini camp load balancer) is the toy locad balancer.\n scmlbd is daemon program.",
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

	// $ scmlbd start で呼び出される start サブコマンドを登録しています
	rootCmd.AddCommand(&subcommands.StartCmd)
}

func main() {
	execute()
}

// この関数は以下のようにターミナルからコマンドを実行したときに最初に呼び出されるエントリーポイントとなる関数です。
// 今回は処理としては特に何もしません
// $ scmlbd
func rootMain(cmd *cobra.Command, args []string) error {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return err
	}
	l := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))
	l.Info("scmlb!!")
	return nil
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
