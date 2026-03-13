package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tornado-bunk/airbridge-server/internal/server"
)

func main() {
	var addr = flag.String("addr", "", "http service address (overrides PORT env)")
	flag.Parse()

	// Get Port from env variable or default to 8080 if not set
	listenAddr := *addr
	if listenAddr == "" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080" // Default port
		}
		listenAddr = ":" + port
	}

	// Initialize structured logger with configurable level via LOG_LEVEL env var.
	// Defaults to INFO in production. Set LOG_LEVEL=DEBUG for verbose output.
	logLevel := slog.LevelInfo
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Initialize the Hub which manages all WebSocket sessions and message routing
	hub := server.NewHub()

	// Start heartbeat monitor to clean up abandoned sessions
	// Checks every 1 minute if a session has been empty for more than 5 minutes
	hub.RunHeartbeat(1*time.Minute, 5*time.Minute)

	mux := http.NewServeMux()

	// Handle standard health check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Sync Relay Server is running"))
	})

	// Handle WebSocket endpoint
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		server.ServeWs(hub, w, r)
	})

	// Setup HTTP Server
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux, // isolated multiplexer avoids DefaultServeMux leaks
	}

	slog.Info("Starting Sync Relay Server", "addr", listenAddr)

	// Start server in a goroutine so it doesn't block
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful Shutdown (Wait for interrupt signal)
	quit := make(chan os.Signal, 1)
	// kill (no param) default os.Interrupt
	// kill -9 is syscall.SIGKILL
	// kill -15 is syscall.SIGTERM
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive our signal.
	<-quit
	slog.Info("Server is shutting down...")

	// Create a deadline to wait for active connections to close.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close the server (this stops accepting new connections and closes idle ones,
	// active websockets will be closed by the Read pumps when the TCP socket drops)
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited properly")
}
