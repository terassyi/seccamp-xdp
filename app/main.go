package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

var (
	httpPort int
	udpPort  int
	tcpPort  int
)

func init() {
	flag.IntVar(&httpPort, "http-port", 8080, "HTTP server running port")
	flag.IntVar(&udpPort, "udp-port", 9090, "UDP server running port")
	flag.IntVar(&tcpPort, "tcp-port", 7070, "TCP server running port")
}

func main() {

	flag.Parse()

	myAddr, err := getMyIpAddress()
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("from: %s: hello!", r.RemoteAddr)
		w.Write([]byte("hello!"))
	})
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("from: %s: ping!", r.RemoteAddr)
		w.Write([]byte("pong"))
	})
	http.HandleFunc("/who", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("from: %s: who are you?", r.RemoteAddr)
		w.Write([]byte(myAddr))
	})

	fmt.Println("start test app")

	go func() {
		if err := serveUdp(ctx, udpPort); err != nil {
			panic(err)
		}
	}()

	go func() {
		if err := serveTCPEcho(ctx, tcpPort); err != nil {
			panic(err)
		}
	}()

	if err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil); err != nil {
		panic(err)
	}
}

func getMyIpAddress() (string, error) {

	ifAddrs, _ := net.InterfaceAddrs()

	for _, ifAddr := range ifAddrs {

		addr, ok := ifAddr.(*net.IPNet)

		if ok && !addr.IP.IsLoopback() && addr.IP.To4() != nil {
			return addr.IP.String(), nil
		}
	}
	return "", fmt.Errorf("failed to get local address")
}

func serveUdp(ctx context.Context, port int) error {
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: port,
	})
	if err != nil {
		return err
	}

	buf := make([]byte, 128)

	fmt.Println("Start UDP Server")

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping UDP server")
			return nil
		default:
			n, addr, err := udpServer.ReadFromUDP(buf)
			if err != nil {
				log.Println(err)
			}
			log.Printf("%s: %s", addr.String(), string(buf[:n]))

		}
	}
}

func serveTCPEcho(ctx context.Context, port int) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping TCP server")
			return nil
		default:
			conn, err := listener.AcceptTCP()
			if err != nil {
				return err
			}
			go handleTCPEcho(ctx, conn)
		}
	}

}

func handleTCPEcho(ctx context.Context, conn *net.TCPConn) {
	defer conn.Close()

	myAddr, _ := getMyIpAddress()

	buf := make([]byte, 4*1024)
	for {
		select {
		case <-ctx.Done():
			log.Println("Finish connection handler")
			return
		default:
			n, err := conn.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				} else {
					log.Println(err)
					continue
				}
			}
			res := fmt.Sprintf("[%s] %s", myAddr, string(buf[:n]))
			_, err = conn.Write([]byte(res))
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}
