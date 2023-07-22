package dosprotection

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var setCmd = cobra.Command{
	Use:   "set",
	Short: "set DoS protection policies",
	RunE:  executeSet,
}

func init() {
	setCmd.Flags().StringP("protocol", "p", "", "target protocol")
	setCmd.Flags().StringP("type", "t", "", "target packet type")
	setCmd.Flags().Int64P("limit", "l", 256, "limit of the number of packets to accept to receive")

	setCmd.MarkFlagRequired("protocol")
}

func executeSet(cmd *cobra.Command, args []string) error {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return err
	}

	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	protocolStr, err := cmd.Flags().GetString("protocol")
	if err != nil {
		return err
	}
	protocol, err := convertProtocol(protocolStr)
	if err != nil {
		return err
	}
	typ, err := cmd.Flags().GetString("type")
	if err != nil {
		return err
	}
	limit, err := cmd.Flags().GetInt64("limit")
	if err != nil {
		return err
	}

	logger.Debug("setup API client", slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
	client, closeF, err := api.NewClient(api.Endpoint, uint32(api.Port))
	if err != nil {

		logger.Error("failed to setup API client", err, slog.String("endpoint", api.Endpoint), slog.Int("port", api.Port))
		return err
	}
	defer closeF()

	if _, err := client.DoSProtectionPolicySet(cmd.Context(), &rpc.DoSProtectionPolicySetRequest{
		Policy: &rpc.DoSProtectionPolicy{
			Protocol: protocol,
			Type:     typ,
			Limit:    limit,
		},
	}); err != nil {
		return err
	}
	return nil
}

func convertProtocol(s string) (int32, error) {
	switch s {
	case "icmp":
		return int32(constants.PROTOCOL_ICMP), nil
	case "tcp":
		return int32(constants.PROTOCOL_TCP), nil
	case "udp":
		return int32(constants.PROTOCOL_UDP), nil
	default:
		return 0, fmt.Errorf("invalid protocol: %s", s)
	}
}
