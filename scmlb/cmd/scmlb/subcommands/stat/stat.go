package stat

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var StatCmd = cobra.Command{
	Use:   "stat",
	Short: "show statistics information",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := logger.Output(constants.LogOutput)
		if err != nil {
			return err
		}
		logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

		logger.Debug("setup API client", slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
		client, closeF, err := api.NewClient(api.Endpoint, uint32(api.Port))
		if err != nil {

			logger.Error("failed to setup API client", err, slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
			return err
		}
		defer closeF()

		res, err := client.Stat(cmd.Context(), &rpc.StatRequest{})
		if err != nil {
			logger.Error("failed to get stat info", err)
			return err
		}

		fmt.Println("scmlb statistics information")
		fmt.Println("Interfaces:")

		for _, iface := range res.Ifaces {
			fmt.Printf("  name: %s\n", iface.Name)
			fmt.Printf("  index: %d\n", iface.Index)
			fmt.Println("  packet counter:")
			fmt.Printf("    icmp: %d\n", iface.Counter.Icmp)
			fmt.Printf("    tcp: %d\n", iface.Counter.Tcp)
			fmt.Printf("    udp: %d\n", iface.Counter.Udp)
		}
		return nil
	},
}
