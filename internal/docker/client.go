package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
)

// Client wraps the Docker SDK client with convenience methods for container management
type Client struct {
	cli *client.Client
	ctx context.Context
}

// NewClient creates a new Docker API client with automatic version negotiation
// Uses environment variables (DOCKER_HOST, DOCKER_API_VERSION, etc.) if set
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

// WithContext returns a shallow copy of the Client using the given context.
// Use this to pass request-scoped contexts so Docker operations are cancelled
// when the HTTP request is cancelled.
func (c *Client) WithContext(ctx context.Context) *Client {
	return &Client{
		cli: c.cli,
		ctx: ctx,
	}
}

// Close gracefully closes the Docker client connection
func (c *Client) Close() error {
	return c.cli.Close()
}

// Ping verifies connectivity to the Docker daemon
func (c *Client) Ping() error {
	_, err := c.cli.Ping(c.ctx)
	return err
}

// ContainerExists checks if a container with the given name exists (running or stopped)
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

// ExecCommand executes a command inside a running container and returns stdout
// Critical for running CrowdSec CLI commands (cscli) for managing decisions, bouncers, etc.
// Properly handles Docker stream protocol to avoid corrupted JSON output
func (c *Client) ExecCommand(containerName string, cmd []string) (string, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return "", err
	}

	// Configure exec without TTY to prevent control characters in output
	// This is critical for commands that return JSON (like cscli)
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

// Regex to match ANSI escape codes
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// stripControlCharacters removes ANSI escape codes and control characters from command output
// Essential for commands returning JSON to prevent parsing errors
// Pre-allocates buffer for better performance
func stripControlCharacters(s string) string {
	// First strip ANSI codes
	s = ansiRegex.ReplaceAllString(s, "")

	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		// Keep printable characters and whitespace (newline, carriage return, tab)
		// Filter out control characters that can corrupt JSON/structured output
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// GetContainerLogs retrieves and returns container logs with optional tail limit
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

// RestartContainer restarts a container with default 30-second timeout
func (c *Client) RestartContainer(name string) error {
	return c.RestartContainerWithTimeout(name, 30)
}

// RestartContainerWithTimeout restarts a container with configurable graceful shutdown timeout
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

// WriteFileToContainer writes content to a file inside a container using the
// Docker copy API. This avoids shell interpolation entirely, preventing
// injection attacks from user-supplied data.
func (c *Client) WriteFileToContainer(containerName, filePath string, content []byte) error {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return err
	}

	// Build a tar archive containing a single file
	dir := filepath.Dir(filePath)
	name := filepath.Base(filePath)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0644,
		Size: int64(len(content)),
	}); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("failed to write tar body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar: %w", err)
	}

	return c.cli.CopyToContainer(c.ctx, containerID, dir, &buf, container.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
	})
}

// ReadFileFromContainer reads a file from inside a container and returns its
// content as a string. Uses the Docker copy API (no shell needed).
func (c *Client) ReadFileFromContainer(containerName, filePath string) (string, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return "", err
	}

	reader, _, err := c.cli.CopyFromContainer(c.ctx, containerID, filePath)
	if err != nil {
		return "", fmt.Errorf("failed to copy from container: %w", err)
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	if _, err := tr.Next(); err != nil {
		return "", fmt.Errorf("failed to read tar entry: %w", err)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return "", fmt.Errorf("failed to read file content: %w", err)
	}
	return string(data), nil
}

// AppendLineToFileInContainer reads a file from a container, appends a line
// after the last list item in the block started by `afterLine`, and writes it
// back. Uses the Docker copy API so no shell interpolation occurs.
//
// For YAML list blocks (e.g. sourceRange:), the new entry is inserted after the
// last existing "- " item in the block so that indentation stays consistent.
func (c *Client) AppendLineToFileInContainer(containerName, filePath, afterLine, newLine string) error {
	content, err := c.ReadFileFromContainer(containerName, filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(content, "\n")

	// Find the index of the section header.
	sectionIdx := -1
	for i, line := range lines {
		if strings.Contains(line, afterLine) {
			sectionIdx = i
			break
		}
	}
	if sectionIdx == -1 {
		return fmt.Errorf("pattern %q not found in %s", afterLine, filePath)
	}

	// Scan forward to find the last list item ("- ") in this block.
	// A line that is non-empty, not a list item, and has less or equal
	// indentation than the section header signals the end of the block.
	// The indentation of the first found list item is captured so the new
	// entry can match it exactly, regardless of what the caller passes.
	sectionIndent := len(lines[sectionIdx]) - len(strings.TrimLeft(lines[sectionIdx], " \t"))
	lastListIdx := sectionIdx // insert right after header if no items found
	detectedIndent := ""
	for i := sectionIdx + 1; i < len(lines); i++ {
		trimmed := strings.TrimLeft(lines[i], " \t")
		if trimmed == "" {
			continue
		}
		lineIndent := len(lines[i]) - len(trimmed)
		if lineIndent <= sectionIndent {
			// Left the block.
			break
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			lastListIdx = i
			if detectedIndent == "" {
				detectedIndent = lines[i][:lineIndent]
			}
		}
	}

	// Apply detected indentation so the new entry always matches existing items.
	// If the block has no existing items, use newLine verbatim.
	insertLine := newLine
	if detectedIndent != "" {
		insertLine = detectedIndent + strings.TrimLeft(newLine, " \t")
	}

	// Insert after the last list item (or after the header if none exist).
	result := make([]string, 0, len(lines)+1)
	result = append(result, lines[:lastListIdx+1]...)
	result = append(result, insertLine)
	result = append(result, lines[lastListIdx+1:]...)

	return c.WriteFileToContainer(containerName, filePath, []byte(strings.Join(result, "\n")))
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

// FileExists checks if a file or directory exists inside a container
func (c *Client) FileExists(containerName, path string) (bool, error) {
	containerID, err := c.GetContainerID(containerName)
	if err != nil {
		return false, err
	}

	_, _, err = c.cli.CopyFromContainer(c.ctx, containerID, path)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// GetHostMountPath maps a container path to its corresponding host mount path
// Useful for accessing container files from the host filesystem
// Returns: (hostPath, found, error)
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

// ValidateImageTag verifies that an image:tag exists locally or in the registry
// Checks local cache first, then queries registry without pulling
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

// PullImage downloads a Docker image from the registry
// Blocks until pull completes or fails
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

	// Preserve network configuration so the container re-attaches to named networks
	var networkingConfig *network.NetworkingConfig
	if inspect.NetworkSettings != nil && len(inspect.NetworkSettings.Networks) > 0 {
		networkingConfig = &network.NetworkingConfig{
			EndpointsConfig: inspect.NetworkSettings.Networks,
		}
	}

	// Create new container with same configuration but new image
	resp, err := c.cli.ContainerCreate(
		c.ctx,
		inspect.Config,
		inspect.HostConfig,
		networkingConfig,
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

// GetLocalImageDigest retrieves the digest of a local image
func (c *Client) GetLocalImageDigest(imageName, tag string) (string, error) {
	fullImage := imageName + ":" + tag
	inspect, _, err := c.cli.ImageInspectWithRaw(c.ctx, fullImage)
	if err != nil {
		return "", fmt.Errorf("failed to inspect local image %s: %w", fullImage, err)
	}

	if len(inspect.RepoDigests) > 0 {
		// RepoDigests format is "image@sha256:digest"
		parts := strings.Split(inspect.RepoDigests[0], "@")
		if len(parts) == 2 {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("no digest found for local image %s", fullImage)
}

// GetRemoteImageDigest retrieves the digest of an image from the registry
func (c *Client) GetRemoteImageDigest(imageName, tag string) (string, error) {
	fullImage := imageName + ":" + tag
	distributionInspect, err := c.cli.DistributionInspect(c.ctx, fullImage, "")
	if err != nil {
		return "", fmt.Errorf("failed to inspect remote image %s: %w", fullImage, err)
	}

	return string(distributionInspect.Descriptor.Digest), nil
}
