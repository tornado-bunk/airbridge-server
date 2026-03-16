package models

import "encoding/json"

// ActionType defines the type of message being sent between client and server
type ActionType string

const (
	ActionRegister     ActionType = "register"       // Sent by client to join a session
	ActionRelayStarted ActionType = "relay_started"  // Sent by Server to both when tunnel is ready
	ActionError        ActionType = "error"          // Sent by Server when something goes wrong
	ActionQueryStatus  ActionType = "query_status"   // Sent by client to query current session health
	ActionStatusReply  ActionType = "status_reply"   // Sent by Server in response to query_status
)

// BaseMessage is the generic wrapper for all JSON messages over WebSocket
type BaseMessage struct {
	Action    ActionType `json:"action"`
	PairingID string     `json:"pairingId"`
	Secret    string     `json:"secret,omitempty"` // Used to authenticate the connection
	Role      Role       `json:"role,omitempty"`   // "mac" or "android" (optional for some actions)
}

// ErrorMessage represents an error event from the server
type ErrorMessage struct {
	Action  ActionType `json:"action"` // Always "error"
	Message string     `json:"message"`
}

// StatusReplyMessage reports the current health of a pairing session
type StatusReplyMessage struct {
	Action        ActionType `json:"action"`    // Always "status_reply"
	PairingID     string     `json:"pairingId"` // Pairing this status refers to
	MacActive     bool       `json:"macActive"`
	AndroidActive bool       `json:"androidActive"`
	BothConnected bool       `json:"bothConnected"`
}

// ParseIncomingMessage is a generic helper to quickly determine the action type
func ParseIncomingMessage(rawPayload []byte) (*BaseMessage, error) {
	var bm BaseMessage
	if err := json.Unmarshal(rawPayload, &bm); err != nil {
		return nil, err
	}
	return &bm, nil
}
