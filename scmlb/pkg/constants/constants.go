package constants

const (
	API_SERVER_PORT     int32  = 5000
	API_SERVER_ENDPOINT string = "127.0.0.1"
)

const (
	PROTOCOL_ICMP uint32 = 1
	PROTOCOL_TCP  uint32 = 6
	PROTOCOL_UDP  uint32 = 17
)

var (
	LogOutput string = "stdout"
	LogLevel  int    = 0
	LogFormat bool   = false
)
