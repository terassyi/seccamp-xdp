package conntrack

import (
	"os"
	"strconv"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/loadbalancer"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var getCmd = cobra.Command{
	Use:   "get",
	Short: "get connection tracking entries",
	RunE:  executeGet,
}

func executeGet(cmd *cobra.Command, args []string) error {
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

	res, err := client.LoadBalancerConntrackGet(cmd.Context(), &rpc.LoadBalancerConntrackGetRequest{})
	if err != nil {
		return err
	}

	logger.DebugCtx(cmd.Context(), "conntrack entries", slog.Any("entries", res.Entries))

	data := [][]string{}

	for _, e := range res.Entries {
		protocol, err := protocols.NewTransportProtocol(uint32(e.Protocol))
		if err != nil {
			return err
		}
		data = append(data, []string{e.SrcAddr, e.DstAddr, strconv.Itoa(int(e.SrcPort)), strconv.Itoa(int(e.DstPort)), protocol.String(), strconv.Itoa(int(e.BackendId)), loadbalancer.ConnectionState(uint8(e.Status)).String(), e.Timestamp.AsTime().UTC().Format(time.RFC3339)})
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"src addr", "dst addr", "src port", "dst port", "protocol", "backend id", "status", "timestamp"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("\t")
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data)

	table.Render()

	return nil
}
