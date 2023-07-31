package lb

import (
	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var deleteCmd = cobra.Command{
	Use:   "delete",
	Short: "delete a lb backend",
	RunE:  executeDelete,
}

func init() {
	deleteCmd.Flags().Int32P("id", "i", 0, "backend id to delete")

	deleteCmd.MarkFlagRequired("id")
}

func executeDelete(cmd *cobra.Command, args []string) error {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return err
	}
	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	id, err := cmd.Flags().GetInt32("id")
	if err != nil {
		return err
	}

	logger.DebugCtx(cmd.Context(), "delete backend", slog.Int("id", int(id)))

	logger.Debug("setup API client", slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
	client, closeF, err := api.NewClient(api.Endpoint, uint32(api.Port))
	if err != nil {

		logger.Error("failed to setup API client", err, slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
		return err
	}
	defer closeF()

	if _, err := client.LoadBalancerDelete(cmd.Context(), &rpc.LoadBalancerDeleteRequest{
		Id: id,
	}); err != nil {
		return err
	}
	return nil
}
