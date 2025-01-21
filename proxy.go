package main

import (
	"fmt"
	"io"
	"net"

	"github.com/rs/zerolog/log"
)

func (s *Server) Proxy(network string, localPort int, remoteAddr string) {
	l, err := net.Listen(network, fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		panic(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}

		go func(conn net.Conn) {
			otherConn, err := s.Dial(network, remoteAddr)
			if err != nil {
				log.Warn().Msgf("cannot connect to %s: %s", remoteAddr, err)
				return
			}
			log.Info().Msgf("proxied 127.0.0.1:%d to %s", localPort, remoteAddr)

			go Copy(conn, otherConn)
			go Copy(otherConn, conn)
		}(conn)
	}
}

func Copy(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	_, err := io.Copy(dst, src)
	// this is scuffed but meh
	if err != nil {
		log.Error().Msg(err.Error())
	}
	dst.Close()
}
