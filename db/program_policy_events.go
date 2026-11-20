package db

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ProgramPolicyEvent is a sanitized, durable record of one mandatory policy
// decision. It deliberately contains no raw tool input, URL path, query, headers,
// cookies, credentials, or model conversation content.
type ProgramPolicyEvent struct {
	ID              int64     `json:"id"`
	TaskID          string    `json:"task_id"`
	ConversationID  *int64    `json:"conversation_id,omitempty"`
	AgentName       string    `json:"agent_name"`
	ToolName        string    `json:"tool_name"`
	DecisionCode    string    `json:"decision_code"`
	Action          string    `json:"action"`
	EventPhase      string    `json:"event_phase"`
	TargetAuthority string    `json:"target_authority"`
	ResolvedIPs     []string  `json:"resolved_ips"`
	PolicyDigest    string    `json:"policy_digest"`
	ExecutionStatus string    `json:"execution_status"`
	Reason          string    `json:"reason"`
	Actor           string    `json:"actor"`
	CreatedAt       time.Time `json:"created_at"`
}

// CreateProgramPolicyEvent appends a sanitized decision to the dedicated event
// stream. It rejects malformed provenance and never accepts caller-supplied actor.
func (d *DB) CreateProgramPolicyEvent(e ProgramPolicyEvent) (int64, error) {
	e.TaskID = strings.TrimSpace(e.TaskID)
	e.ToolName = strings.TrimSpace(e.ToolName)
	e.DecisionCode = strings.TrimSpace(e.DecisionCode)
	e.TargetAuthority = strings.TrimSpace(e.TargetAuthority)
	if e.TaskID == "" || e.ToolName == "" || e.DecisionCode == "" {
		return 0, errors.New("ProgramPolicy event requires task, tool and decision code")
	}
	if e.Action != "allow" && e.Action != "deny" {
		return 0, fmt.Errorf("invalid ProgramPolicy event action %q", e.Action)
	}
	if e.EventPhase == "" {
		e.EventPhase = "decision"
	}
	if e.EventPhase != "decision" && e.EventPhase != "redirect" && e.EventPhase != "dial" {
		return 0, fmt.Errorf("invalid ProgramPolicy event phase %q", e.EventPhase)
	}
	if e.ResolvedIPs == nil {
		e.ResolvedIPs = []string{}
	}
	if len(e.ResolvedIPs) > 32 {
		return 0, errors.New("ProgramPolicy event contains too many resolved IP addresses")
	}
	for n, rawIP := range e.ResolvedIPs {
		ip := net.ParseIP(strings.TrimSpace(rawIP))
		if ip == nil {
			return 0, errors.New("ProgramPolicy event resolved IP must be an IP literal")
		}
		e.ResolvedIPs[n] = ip.String()
	}
	if e.ExecutionStatus != "unknown" && e.ExecutionStatus != "not_executed" {
		return 0, fmt.Errorf("invalid ProgramPolicy execution status %q", e.ExecutionStatus)
	}
	if len(e.TargetAuthority) > 512 || len(e.DecisionCode) > 128 || len(e.ToolName) > 128 || len(e.Reason) > 4096 {
		return 0, errors.New("ProgramPolicy event field exceeds its maximum length")
	}
	if e.TargetAuthority != "" {
		host, portText, err := net.SplitHostPort(e.TargetAuthority)
		port, portErr := strconv.Atoi(portText)
		if err != nil || host == "" || portErr != nil || port < 1 || port > 65535 || strings.ContainsAny(host, "/?#@ \t\r\n") {
			return 0, errors.New("ProgramPolicy target authority must be a host:port pair without URL data")
		}
	}
	if e.PolicyDigest != "" {
		decoded, err := hex.DecodeString(e.PolicyDigest)
		if err != nil || len(decoded) != 32 {
			return 0, errors.New("ProgramPolicy event digest must be an empty string or SHA-256 hex")
		}
		e.PolicyDigest = strings.ToLower(e.PolicyDigest)
	}
	var conversationID any
	if e.ConversationID != nil && *e.ConversationID > 0 {
		conversationID = *e.ConversationID
	}
	var id int64
	err := d.QueryRow(`
INSERT INTO program_policy_events
    (task_id, conversation_id, agent_name, tool_name, decision_code, action,
     event_phase, target_authority, resolved_ips, policy_digest, execution_status, reason, actor)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'system')
RETURNING id`,
		e.TaskID, conversationID, e.AgentName, e.ToolName, e.DecisionCode,
		e.Action, e.EventPhase, e.TargetAuthority, e.ResolvedIPs, e.PolicyDigest, e.ExecutionStatus, e.Reason,
	).Scan(&id)
	return id, err
}

const programPolicyEventColumns = `id, task_id, conversation_id, agent_name, tool_name,
decision_code, action, event_phase, target_authority, resolved_ips, policy_digest, execution_status, reason, actor, created_at`

// ListTaskProgramPolicyEvents returns the newest sanitized policy events for one
// task. The bounded limit prevents an unbounded history read from the API layer.
func (d *DB) ListTaskProgramPolicyEvents(taskID string, limit int) ([]ProgramPolicyEvent, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, errors.New("task id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := d.Query(`SELECT `+programPolicyEventColumns+`
FROM program_policy_events WHERE task_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProgramPolicyEvent, 0)
	for rows.Next() {
		var e ProgramPolicyEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.ConversationID, &e.AgentName,
			&e.ToolName, &e.DecisionCode, &e.Action, &e.EventPhase, &e.TargetAuthority, &e.ResolvedIPs,
			&e.PolicyDigest, &e.ExecutionStatus, &e.Reason, &e.Actor, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetProgramPolicyEvent returns one event, or nil when it does not exist.
func (d *DB) GetProgramPolicyEvent(id int64) (*ProgramPolicyEvent, error) {
	var e ProgramPolicyEvent
	err := d.QueryRow(`SELECT `+programPolicyEventColumns+` FROM program_policy_events WHERE id=$1`, id).
		Scan(&e.ID, &e.TaskID, &e.ConversationID, &e.AgentName, &e.ToolName,
			&e.DecisionCode, &e.Action, &e.EventPhase, &e.TargetAuthority, &e.ResolvedIPs, &e.PolicyDigest,
			&e.ExecutionStatus, &e.Reason, &e.Actor, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}
