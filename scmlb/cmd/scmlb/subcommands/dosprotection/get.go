package dosprotection

import (
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/terassyi/seccamp-xdp/scmlb/cmd/scmlb/api"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/dosprotector"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
)

var getCmd = cobra.Command{
	Use:   "get",
	Short: "get DoS protection policies",
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

	res, err := client.DoSProtectionPolicyGet(cmd.Context(), &rpc.DoSProtectionPolicyGetRequest{})
	if err != nil {
		return err
	}

	logger.DebugCtx(cmd.Context(), "policies", slog.Any("policies", res.Policies))
	data := [][]string{}

	for _, p := range res.Policies {
		protocol, err := protocols.NewTransportProtocol(uint32(p.Protocol))
		if err != nil {
			return err
		}
		data = append(data, []string{strconv.Itoa(int(p.Id)), protocol.String(), p.Type, strconv.Itoa(int(p.Limit)), dosprotector.PolicyStatus(p.Status).String()})
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"id", "protocol", "type", "limit", "status"})
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
