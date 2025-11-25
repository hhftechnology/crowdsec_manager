package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Client wraps the Docker client with helper methods
type Client struct {
	cli *client.Client
	ctx context.Context
}

// NewClient creates a new Docker client
func NewClient() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &Client{
		cli: cli,
		ctx: context.Background(),
	}, nil
}

// Close closes the Docker client
func (c *Client) Close() error {
	return c.cli.Close()
}

// Ping checks if the Docker daemon is accessible
func (c *Client) Ping() error {
	_, err := c.cli.Ping(c.ctx)
	return err
}

// ContainerExists checks if a container with the given name exists
func (c *Client) ContainerExists(name string) (bool, error) {
	containers, err := c.cli.ContainerList(c.ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("name", "^/"+name+"$"),
		),
	})
	if err != nil {
		return false, err
	}
	return len(containers) > 0, nil
}

// IsContainerRunning checks if a container is running
func (c *Client) IsContainerRunning(name string) (bool, error) {
	containers, err := c.cli.ContainerList(c.ctx, container.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("name", "^/"+name+"$"),
			filters.Arg("status", "running"),
		),
	})
	if err != nil {
		return false, err
	}
	return len(containers) > 0, nil
}

// GetContainerID gets the container ID by name
func (c *Client) GetContainerID(name string) (string, error) {
	containers, err := c.cli.ContainerList(c.ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("name", "^/"+name+"$"),
		),
	})
	if err != nil {
		return "", err
	}
	if len(containers) == 0 {
		return "", fmt.Errorf("container %s not found", name)
	}
	return containers[0].ID, nil
}

// ExecCommand executes a command in a container
func (c *Client) ExecCommand(containerName string, cmd []string) (string, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return "", err
	}

	// Create exec instance
	// Tty: false ensures proper stream multiplexing without TTY control characters
	// Env variables disable terminal formatting that can corrupt JSON output
	execConfig := container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Cmd:          cmd,
		Env:          []string{"TERM=dumb", "NO_COLOR=1"},
	}

	execIDResp, err := c.cli.ContainerExecCreate(c.ctx, containerID, execConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	// Attach to exec
	attachResp, err := c.cli.ContainerExecAttach(c.ctx, execIDResp.ID, container.ExecStartOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer attachResp.Close()

	// Use stdcopy to properly demultiplex Docker's stream protocol
	// This removes the 8-byte headers that Docker adds to stdout/stderr
	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attachResp.Reader); err != nil {
		return "", fmt.Errorf("failed to demultiplex exec output: %w", err)
	}

	// Inspect the exec instance to get the exit code
	inspect, err := c.cli.ContainerExecInspect(c.ctx, execIDResp.ID)
	if err != nil {
		return stripControlCharacters(stdout.String()), fmt.Errorf("failed to inspect exec: %w", err)
	}

	// Return stdout output, log stderr if present but exit code is 0
	if inspect.ExitCode != 0 {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = fmt.Sprintf("command failed with exit code %d", inspect.ExitCode)
		}
		return stripControlCharacters(stdout.String()), fmt.Errorf("command failed (exit code %d): %s", inspect.ExitCode, errMsg)
	}

	return stripControlCharacters(stdout.String()), nil
}

// stripControlCharacters removes control characters from output as a defensive measure
// This ensures clean JSON output even if control characters leak through
func stripControlCharacters(s string) string {
	// Build a new string without control characters
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		// Keep printable characters and common whitespace
		// Remove control characters (< 32) except newline, carriage return, and tab
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// GetContainerLogs retrieves logs from a container
func (c *Client) GetContainerLogs(containerName string, tail string) (string, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return "", err
	}

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
	}

	logs, err := c.cli.ContainerLogs(c.ctx, containerID, options)
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}
	defer logs.Close()

	// Use stdcopy to properly demultiplex Docker's log stream protocol
	// This removes the 8-byte headers that Docker adds to each log line
	var stdout, stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, logs)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to demultiplex logs: %w", err)
	}

	// Combine stdout and stderr, marking stderr lines if needed
	var result strings.Builder
	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	if len(stdoutStr) > 0 {
		result.WriteString(stdoutStr)
	}

	if len(stderrStr) > 0 {
		if len(stdoutStr) > 0 && !strings.HasSuffix(stdoutStr, "\n") {
			result.WriteString("\n")
		}
		result.WriteString(stderrStr)
	}

	// Strip control characters and clean up the output
	return stripControlCharacters(result.String()), nil
}

// RestartContainer restarts a container
func (c *Client) RestartContainer(name string) error {
	return c.RestartContainerWithTimeout(name, 30)
}

// RestartContainerWithTimeout restarts a container with a custom timeout
func (c *Client) RestartContainerWithTimeout(name string, timeoutSecs int) error {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return err
	}

	return c.cli.ContainerRestart(c.ctx, containerID, container.StopOptions{
		Timeout: &timeoutSecs,
	})
}

// StopContainer stops a container
func (c *Client) StopContainer(name string) error {
	return c.StopContainerWithTimeout(name, 30)
}

// StopContainerWithTimeout stops a container with a custom timeout
func (c *Client) StopContainerWithTimeout(name string, timeoutSecs int) error {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return err
	}

	return c.cli.ContainerStop(c.ctx, containerID, container.StopOptions{
		Timeout: &timeoutSecs,
	})
}

// StartContainer starts a container
func (c *Client) StartContainer(name string) error {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return err
	}

	return c.cli.ContainerStart(c.ctx, containerID, container.StartOptions{})
}

// ListContainers lists all containers
func (c *Client) ListContainers(all bool) ([]types.Container, error) {
	return c.cli.ContainerList(c.ctx, container.ListOptions{All: all})
}

// CopyFromContainer copies a file from a container
func (c *Client) CopyFromContainer(containerName, srcPath string) (io.ReadCloser, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return nil, err
	}

	reader, _, err := c.cli.CopyFromContainer(c.ctx, containerID, srcPath)
	return reader, err
}

// CopyToContainer copies a file to a container
func (c *Client) CopyToContainer(containerName, dstPath string, content io.Reader) error {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return err
	}

	return c.cli.CopyToContainer(c.ctx, containerID, dstPath, content, container.CopyToContainerOptions{})
}

// GetContainerStats gets container statistics
func (c *Client) GetContainerStats(name string) (*container.StatsResponse, error) {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return nil, err
	}

	stats, err := c.cli.ContainerStats(c.ctx, containerID, false)
	if err != nil {
		return nil, err
	}
	defer stats.Body.Close()

	var statsJSON container.StatsResponse
	if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err != nil {
		return nil, err
	}

	return &statsJSON, nil
}

// InspectContainer inspects a container
func (c *Client) InspectContainer(name string) (*types.ContainerJSON, error) {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return nil, err
	}

	inspect, err := c.cli.ContainerInspect(c.ctx, containerID)
	if err != nil {
		return nil, err
	}

	return &inspect, nil
}

// GetContext returns the context
func (c *Client) GetContext() context.Context {
	return c.ctx
}

// GetClient returns the underlying Docker client
func (c *Client) GetClient() *client.Client {
	return c.cli
}

// FileExists checks if a file exists in a container
func (c *Client) FileExists(containerName, path string) (bool, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return false, err
	}

	_, _, err = c.cli.CopyFromContainer(c.ctx, containerID, path)
	if err != nil {
		if strings.Contains(err.Error(), "No such container:path") ||
			strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// GetHostMountPath finds the host path that is mounted to a given container path
// Returns the host path and true if found, or empty string and false if not found
func (c *Client) GetHostMountPath(containerName, containerPath string) (string, bool, error) {
	inspect, err := c.InspectContainer(containerName)
	if err != nil {
		return "", false, err
	}

	// Check mounts for the container path
	for _, mount := range inspect.Mounts {
		// Check if the container path starts with or matches this mount destination
		if strings.HasPrefix(containerPath, mount.Destination) {
			// Calculate the relative path within the mount
			relativePath := strings.TrimPrefix(containerPath, mount.Destination)
			hostPath := mount.Source + relativePath
			return hostPath, true, nil
		}
	}

	return "", false, nil
}

// ValidateImageTag validates if an image tag exists in the registry
func (c *Client) ValidateImageTag(imageName, tag string) error {
	// Construct full image reference
	fullImage := imageName + ":" + tag

	// Try to inspect the image from registry
	// This will validate against Docker Hub or any configured registry
	_, _, err := c.cli.ImageInspectWithRaw(c.ctx, fullImage)
	if err == nil {
		// Image exists locally, that's good enough
		return nil
	}

	// Image doesn't exist locally, try to get info from registry
	// Use DistributionInspect which queries the registry without pulling
	_, err = c.cli.DistributionInspect(c.ctx, fullImage, "")
	if err != nil {
		return fmt.Errorf("tag '%s' not found for image '%s': %w", tag, imageName, err)
	}

	return nil
}

// PullImage pulls a Docker image from the registry
func (c *Client) PullImage(imageName, tag string) error {
	fullImage := imageName + ":" + tag

	reader, err := c.cli.ImagePull(c.ctx, fullImage, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", fullImage, err)
	}
	defer reader.Close()

	// Read the response to ensure the pull completes
	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return fmt.Errorf("error reading pull response for %s: %w", fullImage, err)
	}

	return nil
}

// RecreateContainer stops, removes, and recreates a container with a new image
func (c *Client) RecreateContainer(name string) error {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return err
	}

	// Get container configuration before stopping
	inspect, err := c.cli.ContainerInspect(c.ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Stop the container
	timeout := 30
	if err := c.cli.ContainerStop(c.ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Remove the container
	if err := c.cli.ContainerRemove(c.ctx, containerID, container.RemoveOptions{}); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	// Create new container with same configuration but new image
	resp, err := c.cli.ContainerCreate(
		c.ctx,
		inspect.Config,
		inspect.HostConfig,
		nil,
		nil,
		name,
	)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Start the new container
	if err := c.cli.ContainerStart(c.ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}
