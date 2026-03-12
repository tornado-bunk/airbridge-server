package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

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

	// Start heartbeat monitor to clean up abandoned sessions
	// Checks every 1 minute if a session has been empty for more than 5 minutes
	hub.RunHeartbeat(1*time.Minute, 5*time.Minute)

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
