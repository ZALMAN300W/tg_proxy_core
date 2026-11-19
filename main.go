package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"tg-ws-proxy/proxy"
)

func main() {
	srv := proxy.NewServer("127.0.0.1:1080")

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	_ = srv.Stop()
}
