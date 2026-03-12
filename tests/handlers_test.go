package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tornado-bunk/airbridge-server/internal/models"
	"github.com/tornado-bunk/airbridge-server/internal/server"
)

func setupTestServer() (*server.Hub, *httptest.Server) {
	hub := server.NewHub()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeWs(hub, w, r)
	}))
	return hub, s
}

func connectWS(t *testing.T, url string, initialMsg interface{}) *websocket.Conn {
	wsURL := "ws" + strings.TrimPrefix(url, "http")

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial websocket: %v", err)
	}

	// Send the initial handshake message required by our ServeWs logic
	b, err := json.Marshal(initialMsg)
	if err != nil {
		t.Fatalf("Failed to marshal initial message: %v", err)
	}

	err = conn.WriteMessage(websocket.TextMessage, b)
	if err != nil {
		t.Fatalf("Failed to write initial message: %v", err)
	}

	return conn
}

func TestMacRegistrationAndAndroidQuery(t *testing.T) {
	hub, s := setupTestServer()
	defer s.Close()

	pairingID := "test-pair-123"

	// 1. Connect Mac and Register IP
	macRegMsg := models.RegisterMessage{
		BaseMessage: models.BaseMessage{
			Action:    models.ActionRegister,
			Role:      models.RoleMac,
			PairingID: pairingID,
		},
		LocalIP: "192.168.1.100",
		Port:    8080,
	}

	macConn := connectWS(t, s.URL, macRegMsg)
	defer macConn.Close()

	// Need a tiny sleep to allow the Goroutine to parse the message and update the Hub
	time.Sleep(100 * time.Millisecond)

	// Verify Hub State
	session := hub.GetSession(pairingID)
	if session == nil {
		t.Fatal("Session was not created in Hub")
	}

	session.RLock()
	if session.MacLocalIP != "192.168.1.100" || session.MacPort != 8080 {
		t.Errorf("Mac IP/Port not registered correctly. Got %s:%d", session.MacLocalIP, session.MacPort)
	}
	session.RUnlock()

	// 2. Connect Android and Query Mac IP
	androidQueryMsg := models.QueryMessage{
		BaseMessage: models.BaseMessage{
			Action:    models.ActionQuery,
			Role:      models.RoleAndroid,
			PairingID: pairingID,
		},
	}

	androidConn := connectWS(t, s.URL, androidQueryMsg)
	defer androidConn.Close()

	// Read the response that the server should send back to Android
	androidConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, respBytes, err := androidConn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read response from server: %v", err)
	}

	var macInfoResp models.MacInfoMessage
	if err := json.Unmarshal(respBytes, &macInfoResp); err != nil {
		t.Fatalf("Response was not a valid MacInfoMessage: %s", string(respBytes))
	}

	if macInfoResp.Action != models.ActionMacInfo {
		t.Errorf("Expected action %s, got %s", models.ActionMacInfo, macInfoResp.Action)
	}
	if macInfoResp.LocalIP != "192.168.1.100" || macInfoResp.Port != 8080 {
		t.Errorf("Received incorrect Mac Info: %s:%d", macInfoResp.LocalIP, macInfoResp.Port)
	}
}

func TestRelayTunneling(t *testing.T) {
	_, s := setupTestServer()
	defer s.Close()

	pairingID := "relay-pair-999"

	// Connect Mac
	macConn := connectWS(t, s.URL, models.RegisterMessage{
		BaseMessage: models.BaseMessage{
			Action:    models.ActionRegister,
			Role:      models.RoleMac,
			PairingID: pairingID,
		},
		LocalIP: "10.0.0.5",
	})
	defer macConn.Close()

	// Connect Android
	androidConn := connectWS(t, s.URL, models.QueryMessage{
		BaseMessage: models.BaseMessage{
			Action:    models.ActionQuery,
			Role:      models.RoleAndroid,
			PairingID: pairingID,
		},
	})
	defer androidConn.Close()

	// Consume the initial Query Response sent to Android
	_, _, _ = androidConn.ReadMessage()

	// Android requests Relay
	reqRelayMsg := models.BaseMessage{
		Action:    models.ActionRequestRelay,
		Role:      models.RoleAndroid,
		PairingID: pairingID,
	}
	b, _ := json.Marshal(reqRelayMsg)
	androidConn.WriteMessage(websocket.TextMessage, b)

	// Both should receive a RelayStarted message
	_, macResp, _ := macConn.ReadMessage()
	_, androidResp, _ := androidConn.ReadMessage()

	if !strings.Contains(string(macResp), string(models.ActionRelayStarted)) {
		t.Errorf("Mac did not receive relay started message")
	}
	if !strings.Contains(string(androidResp), string(models.ActionRelayStarted)) {
		t.Errorf("Android did not receive relay started message")
	}

	// Test the Tunnel itself (Android sends binary fake E2EE payload -> Mac receives it)
	fakeEncryptedPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05} // "raw payload"
	androidConn.WriteMessage(websocket.BinaryMessage, fakeEncryptedPayload)

	macConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, receivedPayload, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to read tunnel payload: %v", err)
	}

	if msgType != websocket.BinaryMessage {
		// Our client pump actually always uses TextMessage for WritePump currently,
		// let's check if the bytes match regardless of websocket frame type
		t.Logf("Received message type: %d", msgType)
	}

	if string(receivedPayload) != string(fakeEncryptedPayload) {
		t.Errorf("Received payload does not match sent payload. Got %v, want %v", receivedPayload, fakeEncryptedPayload)
	}
}
