package docker

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
)

// ExecSession represents an interactive exec session attached to a container
type ExecSession struct {
	conn   io.ReadWriteCloser
	execID string
	client *Client
}

// ExecInteractive creates a TTY exec session inside a container.
// Returns an ExecSession with Read/Write/Close for bidirectional IO.
func ExecInteractive(c *Client, containerName string, cmd []string, env []string) (*ExecSession, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return nil, fmt.Errorf("container not found: %w", err)
	}

	execConfig := container.ExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          cmd,
		Env:          env,
	}

	execResp, err := c.cli.ContainerExecCreate(c.ctx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %w", err)
	}

	attachResp, err := c.cli.ContainerExecAttach(c.ctx, execResp.ID, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %w", err)
	}

	return &ExecSession{
		conn:   attachResp.Conn,
		execID: execResp.ID,
		client: c,
	}, nil
}

// Read reads from the exec session stdout/stderr
func (s *ExecSession) Read(p []byte) (int, error) {
	return s.conn.Read(p)
}

// Write writes to the exec session stdin
func (s *ExecSession) Write(p []byte) (int, error) {
	return s.conn.Write(p)
}

// Close closes the exec session connection
func (s *ExecSession) Close() error {
	return s.conn.Close()
}

// Resize resizes the TTY of the exec session
func (s *ExecSession) Resize(cols, rows uint) error {
	return s.client.cli.ContainerExecResize(s.client.ctx, s.execID, container.ResizeOptions{
		Width:  cols,
		Height: rows,
	})
}

// HandleResize parses a JSON resize message and applies it.
// Returns true if the message was a resize command, false otherwise.
func (s *ExecSession) HandleResize(data []byte) bool {
	var msg struct {
		Type string `json:"type"`
		Cols uint   `json:"cols"`
		Rows uint   `json:"rows"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return false
	}
	if msg.Type != "resize" || msg.Cols == 0 || msg.Rows == 0 {
		return false
	}
	if err := s.Resize(msg.Cols, msg.Rows); err != nil {
		// Non-fatal: resize may fail on some containers
		return true
	}
	return true
}
