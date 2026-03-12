package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tornado-bunk/airbridge-server/internal/server"
)

func main() {
	var addr = flag.String("addr", "", "http service address (overrides PORT env)")
	flag.Parse()

	// 1. Determine Port (Env Var fallback)
	listenAddr := *addr
	if listenAddr == "" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080" // Default port
		}
		listenAddr = ":" + port
	}

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

	// 2. Setup HTTP Server
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: nil, // uses DefaultServeMux from http.HandleFunc
	}

	slog.Info("Starting Sync Relay Server", "addr", listenAddr)

	// 3. Start server in a goroutine so it doesn't block
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// 4. Graceful Shutdown (Wait for interrupt signal)
	quit := make(chan os.Signal, 1)
	// kill (no param) default os.Interrupt
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need add it
	// kill -2 is syscall.SIGINT
	// kill -15 is syscall.SIGTERM
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive our signal.
	<-quit
	slog.Info("Server is shutting down...")

	// Create a deadline to wait for active connections to close.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 5. Close the server (this stops accepting new connections and closes idle ones,
	// active websockets will be closed by the Read pumps when the TCP socket drops)
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited properly")
}
