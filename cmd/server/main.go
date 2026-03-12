package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/tornado-bunk/airbridge-server/internal/server"
)

func main() {
	var addr = flag.String("addr", ":8080", "http service address")
	flag.Parse()

	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("Starting Sync Relay Server", "addr", *addr)

	hub := server.NewHub()

	// Handle standard health check
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Sync Relay Server is running"))
	})

	// Handle WebSocket endpoint
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		server.ServeWs(hub, w, r)
	})

	// Start server
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
