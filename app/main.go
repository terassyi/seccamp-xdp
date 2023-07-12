package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

var port int

func init() {
	flag.IntVar(&port, "port", 8080, "HTTP server running port")
}

func main() {

	flag.Parse()

	myAddr, err := getMyIpAddress()
	if err != nil {
		panic(err)
	}

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

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
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
