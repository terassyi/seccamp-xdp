package lb

import (
	"net/netip"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var SetCmd = cobra.Command{
	Use:   "set",
	Short: "set lb backend",
	RunE:  executeSet,
}

func init() {
	SetCmd.Flags().StringP("name", "n", "", "name of a lb backend")
	SetCmd.Flags().StringP("address", "a", "", "IP address of a lb backend")
	SetCmd.Flags().StringP("healthcheck", "c", "/", "healthchecing path")

	SetCmd.MarkFlagRequired("name")
	SetCmd.MarkFlagRequired("address")
	SetCmd.MarkFlagRequired("healthcheck")
}

func executeSet(cmd *cobra.Command, args []string) error {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return err
	}
	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	name, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}
	address, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	hc, err := cmd.Flags().GetString("healthcheck")
	if err != nil {
		return err
	}

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}

	logger.DebugCtx(cmd.Context(), "set backend", slog.String("name", name))

	logger.Debug("setup API client", slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
	client, closeF, err := api.NewClient(api.Endpoint, uint32(api.Port))
	if err != nil {

		logger.Error("failed to setup API client", err, slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
		return err
	}
	defer closeF()

	if _, err := client.LoadBalancerSet(cmd.Context(), &rpc.LoadBalancerSetRequest{
		Address:     addr.String(),
		Name:        name,
		Healthcheck: hc,
	}); err != nil {
		return err
	}

	return nil
}
