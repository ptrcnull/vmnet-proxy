package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/armon/go-socks5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	iface := flag.String("iface", "en0", "host interface to use")
	debug := flag.Bool("debug", false, "sets log level to debug")
	trace := flag.Bool("trace", false, "sets log level to trace")
	help := flag.Bool("help", false, "shows help")

	// chosen by fair dice roll
	hostLinkAddr := flag.String("mac", "00:1A:70:54:A6:93", "MAC address to use")
	hostProtoAddr := flag.String("ip", "192.168.255.10/24", "IP address to use (with prefix)")
	gateProtoAddr := flag.String("gateway", "192.168.255.1", "gateway IP address")

	socks := flag.String("socks5", "none", "listen address for socks5 proxy")

	flag.Parse()

	if *help {
		usage(0)
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if *trace {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}

	server, err := NewServer(*iface, *hostLinkAddr, *hostProtoAddr, *gateProtoAddr)
	if err != nil {
		log.Fatal().Msgf("unable to start the server: %s", err)
	}
	defer server.Close()

	go server.Loop()

	for _, arg := range flag.Args() {
		parts := strings.Split(arg, ":")
		if len(parts) != 4 {
			usage(1)
		}
		network := parts[0]
		localPort, err := strconv.Atoi(parts[1])
		if err != nil {
			panic(err)
		}
		remoteAddr := parts[2] + ":" + parts[3]
		go server.Proxy(network, localPort, remoteAddr)
	}

	if socks != nil && *socks != "none" {
		sockserv, err := socks5.New(&socks5.Config{
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return server.Dial(network, addr)
			},
		})
		if err != nil {
			panic(err)
		}
		go func() {
			err := sockserv.ListenAndServe("tcp", *socks)
			if err != nil {
				panic(err)
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info().Msg("closing down")

	server.Shutdown()
}

func usage(exitcode int) {
	fmt.Println("usage: ./uwu protocol:local-port:remote-host:remote-port")
	os.Exit(exitcode)
}
