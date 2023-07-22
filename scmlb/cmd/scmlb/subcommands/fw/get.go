package fw

import (
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var getCmd = cobra.Command{
	Use:   "get",
	Short: "get fire wall rules",
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

	rules, err := client.FireWallRuleGet(cmd.Context(), &rpc.FireWallRuleGetRequest{})
	if err != nil {
		return err
	}

	data := [][]string{}

	for _, r := range rules.Rules {
		proto, err := protocols.NewTransportProtocol(uint32(r.Protocol))
		if err != nil {
			return err
		}
		data = append(data, []string{strconv.Itoa(int(r.Id)), r.Prefix, strconv.Itoa(int(r.FromSrcPort)), strconv.Itoa(int(r.ToSrcPort)), strconv.Itoa(int(r.FromDstPort)), strconv.Itoa(int(r.ToDstPort)), proto.String(), strconv.Itoa(int(r.Count))})
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"id", "network", "srcfromport", "srctoport", "dstfromport", "dsttoport", "protocol", "dropped"})
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
