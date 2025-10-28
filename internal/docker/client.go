package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
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
	execConfig := container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
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

	// Read output
	output, err := io.ReadAll(attachResp.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to read exec output: %w", err)
	}

	return string(output), nil
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

	output, err := io.ReadAll(logs)
	if err != nil {
		return "", fmt.Errorf("failed to read logs: %w", err)
	}

	return string(output), nil
}

// RestartContainer restarts a container
func (c *Client) RestartContainer(name string) error {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return err
	}

	timeout := 30
	return c.cli.ContainerRestart(c.ctx, containerID, container.StopOptions{
		Timeout: &timeout,
	})
}

// StopContainer stops a container
func (c *Client) StopContainer(name string) error {
	containerID, err := c.GetContainerID(name)
	if err != nil {
		return err
	}

	timeout := 30
	return c.cli.ContainerStop(c.ctx, containerID, container.StopOptions{
		Timeout: &timeout,
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
