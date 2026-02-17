package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// ContainerInfo holds summarized container state.
type ContainerInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	State  string `json:"state"`
	Status string `json:"status"`
	Health string `json:"health"`
}

// Client wraps the Docker SDK client.
type Client struct {
	cli *client.Client
}

// NewClient creates a Docker client from the default environment.
func NewClient() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}
	slog.Info("docker client initialized")
	return &Client{cli: cli}, nil
}

// Close closes the underlying Docker client.
func (c *Client) Close() error {
	return c.cli.Close()
}

// ListContainers returns info for all running containers.
func (c *Client) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	result := make([]ContainerInfo, 0, len(containers))
	for _, ctr := range containers {
		name := ""
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}
		health := ""
		if ctr.Status != "" && strings.Contains(ctr.Status, "(") {
			// Extract health from status like "Up 5 hours (healthy)"
			if idx := strings.Index(ctr.Status, "("); idx != -1 {
				end := strings.Index(ctr.Status[idx:], ")")
				if end != -1 {
					health = ctr.Status[idx+1 : idx+end]
				}
			}
		}
		result = append(result, ContainerInfo{
			ID:     ctr.ID[:12],
			Name:   name,
			Image:  ctr.Image,
			State:  ctr.State,
			Status: ctr.Status,
			Health: health,
		})
	}
	return result, nil
}

// InspectContainer returns details for a single container by name.
func (c *Client) InspectContainer(ctx context.Context, name string) (*ContainerInfo, error) {
	ctr, err := c.cli.ContainerInspect(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("inspect container %q: %w", name, err)
	}

	health := ""
	if ctr.State.Health != nil {
		health = string(ctr.State.Health.Status)
	}

	return &ContainerInfo{
		ID:     ctr.ID[:12],
		Name:   strings.TrimPrefix(ctr.Name, "/"),
		Image:  ctr.Config.Image,
		State:  ctr.State.Status,
		Status: ctr.State.Status,
		Health: health,
	}, nil
}

// StartContainer starts a stopped container.
func (c *Client) StartContainer(ctx context.Context, name string) error {
	return c.cli.ContainerStart(ctx, name, container.StartOptions{})
}

// StopContainer stops a running container with a 30-second timeout.
func (c *Client) StopContainer(ctx context.Context, name string) error {
	timeout := 30
	return c.cli.ContainerStop(ctx, name, container.StopOptions{Timeout: &timeout})
}

// RestartContainer restarts a container with a 30-second timeout.
func (c *Client) RestartContainer(ctx context.Context, name string) error {
	timeout := 30
	return c.cli.ContainerRestart(ctx, name, container.StopOptions{Timeout: &timeout})
}

// ExecInContainer executes a command inside a container and returns combined output.
// CRITICAL: cmd is a string slice — no shell interpolation occurs.
func (c *Client) ExecInContainer(ctx context.Context, containerName string, cmd []string) (string, error) {
	execCfg := types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	execID, err := c.cli.ContainerExecCreate(ctx, containerName, execCfg)
	if err != nil {
		return "", fmt.Errorf("exec create in %q: %w", containerName, err)
	}

	resp, err := c.cli.ContainerExecAttach(ctx, execID.ID, types.ExecStartCheck{})
	if err != nil {
		return "", fmt.Errorf("exec attach in %q: %w", containerName, err)
	}
	defer resp.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, resp.Reader); err != nil {
		return "", fmt.Errorf("read exec output: %w", err)
	}

	// Check exit code.
	inspect, err := c.cli.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return stdout.String(), fmt.Errorf("exec inspect: %w", err)
	}
	if inspect.ExitCode != 0 {
		return stdout.String(), fmt.Errorf("command exited with code %d: %s", inspect.ExitCode, stderr.String())
	}

	return stdout.String(), nil
}

// ReadFileFromContainer copies a file out of a container and returns its contents.
func (c *Client) ReadFileFromContainer(ctx context.Context, containerName, path string) ([]byte, error) {
	reader, _, err := c.cli.CopyFromContainer(ctx, containerName, path)
	if err != nil {
		return nil, fmt.Errorf("copy from container %q path %q: %w", containerName, path, err)
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	if _, err := tr.Next(); err != nil {
		return nil, fmt.Errorf("read tar header: %w", err)
	}

	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, fmt.Errorf("read file content: %w", err)
	}
	return data, nil
}

// WriteFileToContainer writes content to a file inside a container via tar archive.
func (c *Client) WriteFileToContainer(ctx context.Context, containerName, path string, content []byte) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Determine the file name from the path.
	parts := strings.Split(path, "/")
	fileName := parts[len(parts)-1]
	dir := strings.Join(parts[:len(parts)-1], "/")

	if err := tw.WriteHeader(&tar.Header{
		Name: fileName,
		Mode: 0o644,
		Size: int64(len(content)),
	}); err != nil {
		return fmt.Errorf("write tar header: %w", err)
	}

	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("write tar content: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}

	return c.cli.CopyToContainer(ctx, containerName, dir, &buf, types.CopyToContainerOptions{})
}

// GetContainerLogs returns the last N lines of a container's logs.
func (c *Client) GetContainerLogs(ctx context.Context, containerName string, lines int) (string, error) {
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", lines),
	}

	reader, err := c.cli.ContainerLogs(ctx, containerName, opts)
	if err != nil {
		return "", fmt.Errorf("get logs for %q: %w", containerName, err)
	}
	defer reader.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, reader); err != nil {
		// Some containers don't use multiplexed streams; fall back to raw read.
		reader2, _ := c.cli.ContainerLogs(ctx, containerName, opts)
		defer reader2.Close()
		data, _ := io.ReadAll(reader2)
		return string(data), nil
	}

	combined := stdout.String()
	if s := stderr.String(); s != "" {
		combined += "\n" + s
	}
	return combined, nil
}

// StreamContainerLogs returns a reader for following container logs in real time.
func (c *Client) StreamContainerLogs(ctx context.Context, containerName string) (io.ReadCloser, error) {
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "50",
	}

	reader, err := c.cli.ContainerLogs(ctx, containerName, opts)
	if err != nil {
		return nil, fmt.Errorf("stream logs for %q: %w", containerName, err)
	}
	return reader, nil
}
