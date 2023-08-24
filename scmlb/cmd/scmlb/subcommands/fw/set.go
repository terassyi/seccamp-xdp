package fw

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var setCmd = cobra.Command{
	Use:   "set",
	Short: "set a fire wall rule",
	RunE:  executeSet,
}

func init() {
	setCmd.Flags().StringP("src-network", "n", "0.0.0.0/0", "source network range to deny by fire wall")
	setCmd.Flags().StringP("protocol", "t", "any", "transport protocols to deny(expected value is any/icmp/tcp/udp)")
	setCmd.Flags().StringP("src-port", "s", "0", "port range to deny(example: 22, 5000-6000)")
	setCmd.Flags().StringP("dst-port", "d", "0", "port range to deny(example: 22, 5000-6000)")

	setCmd.MarkFlagRequired("src-network")
}

func executeSet(cmd *cobra.Command, args []string) error {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return err
	}
	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	networkStr, err := cmd.Flags().GetString("src-network")
	if err != nil {
		return err
	}
	protocolStr, err := cmd.Flags().GetString("protocol")
	if err != nil {
		return err
	}
	srcPortRangeStr, err := cmd.Flags().GetString("src-port")
	if err != nil {
		return err
	}
	dstPortRangeStr, err := cmd.Flags().GetString("dst-port")
	if err != nil {
		return err
	}

	network, err := netip.ParsePrefix(networkStr)
	if err != nil {
		return err
	}

	protocol, err := protocols.TransportProtocolFromString(protocolStr)
	if err != nil {
		return err
	}
	srcFrom, srcTo, err := splitPortRange(srcPortRangeStr)
	if err != nil {
		return err
	}
	dstFrom, dstTo, err := splitPortRange(dstPortRangeStr)
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

	_, err = client.FireWallRuleSet(cmd.Context(), &rpc.FireWallRuleSetRqeust{
		Rule: &rpc.FireWallRule{
			Prefix:      network.String(),
			Protocol:    int32(protocol),
			FromSrcPort: int32(srcFrom),
			ToSrcPort:   int32(srcTo),
			FromDstPort: int32(dstFrom),
			ToDstPort:   int32(dstTo),
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func splitPortRange(s string) (uint32, uint32, error) {
	ss := strings.Split(s, "-")
	if len(ss) == 1 {
		n, err := strconv.Atoi(ss[0])
		if err != nil {
			return 0, 0, err
		}
		return uint32(n), uint32(n), nil
	}
	if len(ss) == 2 {
		from, err := strconv.Atoi(ss[0])
		if err != nil {
			return 0, 0, err
		}
		to, err := strconv.Atoi(ss[1])
		if err != nil {
			return 0, 0, err
		}
		return uint32(from), uint32(to), nil
	}
	return 0, 0, fmt.Errorf("invalid port range: %s", s)
}
