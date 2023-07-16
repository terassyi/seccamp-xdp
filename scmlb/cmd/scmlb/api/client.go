package api

import (
	"fmt"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	Endpoint string = "127.0.0.1"
	Port     int    = 5000
)

func NewClient(endpoint string, port uint32) (rpc.ScmLbApiClient, func() error, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", endpoint, port), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, nil, err
	}
	client := rpc.NewScmLbApiClient(conn)
	finalizer := func() error {
		return conn.Close()
	}
	return client, finalizer, nil
}
