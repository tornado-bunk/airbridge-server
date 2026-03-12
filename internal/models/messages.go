package models

import "encoding/json"

// ActionType defines the type of message being sent between client and server
type ActionType string

const (
	ActionRegister     ActionType = "register"      // Sent by Mac to register its IP
	ActionQuery        ActionType = "query"         // Sent by Android to request Mac's IP
	ActionMacInfo      ActionType = "mac_info"      // Sent by Server to Android containing Mac IP
	ActionRequestRelay ActionType = "request_relay" // Sent by Android to start tunneling
	ActionRelayStarted ActionType = "relay_started" // Sent by Server to both when tunnel is ready
	ActionError        ActionType = "error"         // Sent by Server when something goes wrong
)

// BaseMessage is the generic wrapper for all JSON messages over WebSocket
type BaseMessage struct {
	Action    ActionType `json:"action"`
	PairingID string     `json:"pairingId"`
	Secret    string     `json:"secret,omitempty"` // Used to authenticate the connection
	Role      Role       `json:"role,omitempty"`   // "mac" or "android" (optional for some actions)
}

// RegisterMessage represents the payload sent by the Mac to register its connection
type RegisterMessage struct {
	BaseMessage
	LocalIP string `json:"localIp"` // E.g., "192.168.1.50" or "10.147.17.2"
	Port    int    `json:"port"`    // E.g., 8080
}

// QueryMessage represents the payload sent by Android to find the Mac
type QueryMessage struct {
	BaseMessage
}

// MacInfoMessage represents the server's response to an Android Query, providing the IP
type MacInfoMessage struct {
	Action  ActionType `json:"action"` // Always "mac_info"
	LocalIP string     `json:"localIp"`
	Port    int        `json:"port"`
}

// ErrorMessage represents an error event from the server
type ErrorMessage struct {
	Action  ActionType `json:"action"` // Always "error"
	Message string     `json:"message"`
}

// ParseIncomingMessage is a generic helper to quickly determine the action type
func ParseIncomingMessage(rawPayload []byte) (*BaseMessage, error) {
	var bm BaseMessage
	if err := json.Unmarshal(rawPayload, &bm); err != nil {
		return nil, err
	}
	return &bm, nil
}
