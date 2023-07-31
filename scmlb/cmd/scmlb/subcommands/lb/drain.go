package lb

import (
	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var drainCmd = cobra.Command{
	Use:   "drain",
	Short: "drain existing connection. mark unavailable to target backend.",
	RunE:  executeDrain,
}

func init() {
	drainCmd.Flags().Int32P("id", "i", 0, "backend id to delete")

	drainCmd.MarkFlagRequired("id")
}

func executeDrain(cmd *cobra.Command, args []string) error {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return err
	}
	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	id, err := cmd.Flags().GetInt32("id")
	if err != nil {
		return err
	}

	logger.DebugCtx(cmd.Context(), "drain backend", slog.Int("id", int(id)))

	logger.Debug("setup API client", slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
	client, closeF, err := api.NewClient(api.Endpoint, uint32(api.Port))
	if err != nil {

		logger.Error("failed to setup API client", err, slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
		return err
	}
	defer closeF()

	if _, err := client.LoadBalancerDrain(cmd.Context(), &rpc.LoadBalancerDrainRequest{
		Id: id,
	}); err != nil {
		return err
	}
	return nil
}
