package traefikconfig

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"

	"gopkg.in/yaml.v3"
)

const ManagedWhitelistMiddlewareName = "crowdsec-manager-ip-whitelist"

type ReadResult struct {
	Content     string
	SourcePaths []string
	Target      config.TraefikDynamicConfigTarget
}

func Resolve(configuredPath string) (config.TraefikDynamicConfigTarget, error) {
	return config.ResolveTraefikDynamicConfigTarget(configuredPath)
}

func ManagedFilePath(configuredPath string) (string, error) {
	target, err := Resolve(configuredPath)
	if err != nil {
		return "", err
	}
	return target.ManagedFilePath, nil
}

func ReadContainer(dockerClient *docker.Client, containerName, configuredPath string) (ReadResult, error) {
	target, err := Resolve(configuredPath)
	if err != nil {
		return ReadResult{}, err
	}

	if target.Mode == config.TraefikDynamicConfigModeFile {
		content, err := dockerClient.ReadFileFromContainer(containerName, target.ManagedFilePath)
		if err != nil {
			return ReadResult{}, err
		}
		return ReadResult{
			Content:     content,
			SourcePaths: []string{target.ManagedFilePath},
			Target:      target,
		}, nil
	}

	files, err := readYAMLFilesFromContainerDirectory(dockerClient, containerName, target.ConfiguredPath)
	if err != nil {
		return ReadResult{}, err
	}
	return ReadResult{
		Content:     combineYAMLDocuments(files),
		SourcePaths: sortedKeys(files),
		Target:      target,
	}, nil
}

func ReadHost(cfg *config.Config, configuredPath string) (ReadResult, error) {
	target, err := Resolve(configuredPath)
	if err != nil {
		return ReadResult{}, err
	}

	if target.Mode == config.TraefikDynamicConfigModeFile {
		hostPath, err := containerPathToHostPath(cfg, target.ManagedFilePath)
		if err != nil {
			return ReadResult{}, err
		}
		data, err := os.ReadFile(hostPath)
		if err != nil {
			return ReadResult{}, err
		}
		return ReadResult{
			Content:     string(data),
			SourcePaths: []string{target.ManagedFilePath},
			Target:      target,
		}, nil
	}

	hostDir, err := containerPathToHostPath(cfg, target.ConfiguredPath)
	if err != nil {
		return ReadResult{}, err
	}
	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return ReadResult{}, err
	}

	files := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !isYAMLFileName(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(hostDir, entry.Name()))
		if err != nil {
			return ReadResult{}, err
		}
		files[path.Join(target.ConfiguredPath, entry.Name())] = string(data)
	}

	return ReadResult{
		Content:     combineYAMLDocuments(files),
		SourcePaths: sortedKeys(files),
		Target:      target,
	}, nil
}

func ReadManagedContainer(dockerClient *docker.Client, containerName, configuredPath string) (string, string, error) {
	target, err := Resolve(configuredPath)
	if err != nil {
		return "", "", err
	}

	if target.Mode == config.TraefikDynamicConfigModeDirectory {
		exists, err := dockerClient.FileExists(containerName, target.ManagedFilePath)
		if err != nil {
			return "", "", err
		}
		if !exists {
			return "", target.ManagedFilePath, nil
		}
	}

	content, err := dockerClient.ReadFileFromContainer(containerName, target.ManagedFilePath)
	if err != nil {
		return "", "", err
	}
	return content, target.ManagedFilePath, nil
}

func WriteManagedContainer(dockerClient *docker.Client, containerName, configuredPath string, content []byte) (string, error) {
	target, err := Resolve(configuredPath)
	if err != nil {
		return "", err
	}
	if err := dockerClient.WriteFileToContainer(containerName, target.ManagedFilePath, content); err != nil {
		return "", err
	}
	return target.ManagedFilePath, nil
}

func ManagedHostFilePath(cfg *config.Config, configuredPath string) (string, error) {
	target, err := Resolve(configuredPath)
	if err != nil {
		return "", err
	}
	return containerPathToHostPath(cfg, target.ManagedFilePath)
}

func containerPathToHostPath(cfg *config.Config, containerPath string) (string, error) {
	switch {
	case containerPath == "/etc/traefik":
		return filepath.Join(cfg.ConfigDir, "traefik"), nil
	case strings.HasPrefix(containerPath, "/etc/traefik/"):
		return filepath.Join(cfg.ConfigDir, "traefik", filepath.FromSlash(strings.TrimPrefix(containerPath, "/etc/traefik/"))), nil
	case containerPath == "/rules":
		return filepath.Join(cfg.ConfigDir, "traefik", "rules"), nil
	case strings.HasPrefix(containerPath, "/rules/"):
		return filepath.Join(cfg.ConfigDir, "traefik", "rules", filepath.FromSlash(strings.TrimPrefix(containerPath, "/rules/"))), nil
	default:
		return "", fmt.Errorf("unsupported Traefik container path: %s", containerPath)
	}
}

func readYAMLFilesFromContainerDirectory(dockerClient *docker.Client, containerName, dirPath string) (map[string]string, error) {
	reader, err := dockerClient.CopyFromContainer(containerName, dirPath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	files := map[string]string{}
	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.FileInfo().IsDir() || !isYAMLFileName(hdr.Name) {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		fullPath := archiveEntryToContainerPath(dirPath, hdr.Name)
		files[fullPath] = string(data)
	}

	return files, nil
}

func archiveEntryToContainerPath(basePath, entryName string) string {
	cleanBase := path.Clean(basePath)
	cleanEntry := path.Clean(strings.TrimPrefix(entryName, "./"))
	baseName := path.Base(cleanBase)

	switch {
	case cleanEntry == "." || cleanEntry == "":
		return cleanBase
	case cleanEntry == baseName:
		return cleanBase
	case strings.HasPrefix(cleanEntry, baseName+"/"):
		return path.Join(cleanBase, strings.TrimPrefix(cleanEntry, baseName+"/"))
	default:
		return path.Join(cleanBase, cleanEntry)
	}
}

func isYAMLFileName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

func combineYAMLDocuments(files map[string]string) string {
	paths := sortedKeys(files)
	var builder strings.Builder

	for _, filePath := range paths {
		content := strings.TrimSpace(files[filePath])
		if content == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString("\n")
		}
		builder.WriteString("---\n")
		builder.WriteString("# Source: ")
		builder.WriteString(filePath)
		builder.WriteString("\n")
		builder.WriteString(content)
		builder.WriteString("\n")
	}

	return strings.TrimSpace(builder.String())
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func UpsertWhitelistEntry(content, entry string) (string, error) {
	doc, err := parseYAMLDocument(content)
	if err != nil {
		return "", err
	}

	sourceRange := ensureWhitelistSourceRange(doc.Content[0])
	for _, item := range sourceRange.Content {
		if strings.TrimSpace(item.Value) == entry {
			return marshalYAMLDocument(doc)
		}
	}

	sourceRange.Content = append(sourceRange.Content, &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: entry,
	})

	return marshalYAMLDocument(doc)
}

func RemoveWhitelistEntry(content, entry string) (string, bool, error) {
	doc, err := parseYAMLDocument(content)
	if err != nil {
		return "", false, err
	}

	sourceRange, ok := findWhitelistSourceRange(doc.Content[0])
	if !ok {
		out, err := marshalYAMLDocument(doc)
		return out, false, err
	}

	filtered := make([]*yaml.Node, 0, len(sourceRange.Content))
	removed := false
	for _, item := range sourceRange.Content {
		if strings.TrimSpace(item.Value) == entry {
			removed = true
			continue
		}
		filtered = append(filtered, item)
	}
	sourceRange.Content = filtered

	out, err := marshalYAMLDocument(doc)
	return out, removed, err
}

func parseYAMLDocument(content string) (*yaml.Node, error) {
	var doc yaml.Node
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
		return &doc, nil
	}

	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse Traefik dynamic config: %w", err)
	}
	if len(doc.Content) == 0 {
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
		return &doc, nil
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Traefik dynamic config root is not a mapping")
	}
	return &doc, nil
}

func marshalYAMLDocument(doc *yaml.Node) (string, error) {
	var builder strings.Builder
	encoder := yaml.NewEncoder(&builder)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return strings.TrimSpace(builder.String()) + "\n", nil
}

func ensureWhitelistSourceRange(root *yaml.Node) *yaml.Node {
	httpNode := findOrCreateMap(root, "http")
	middlewaresNode := findOrCreateMap(httpNode, "middlewares")
	whitelistNode := findOrCreateMap(middlewaresNode, ManagedWhitelistMiddlewareName)
	ipAllowListNode := findOrCreateMap(whitelistNode, "ipAllowList")
	return findOrCreateSequence(ipAllowListNode, "sourceRange")
}

func findWhitelistSourceRange(root *yaml.Node) (*yaml.Node, bool) {
	httpNode, ok := findMap(root, "http")
	if !ok {
		return nil, false
	}
	middlewaresNode, ok := findMap(httpNode, "middlewares")
	if !ok {
		return nil, false
	}
	whitelistNode, ok := findMap(middlewaresNode, ManagedWhitelistMiddlewareName)
	if !ok {
		return nil, false
	}
	ipAllowListNode, ok := findMap(whitelistNode, "ipAllowList")
	if !ok {
		return nil, false
	}
	sourceRangeNode, ok := findSequence(ipAllowListNode, "sourceRange")
	return sourceRangeNode, ok
}

func findMap(parent *yaml.Node, key string) (*yaml.Node, bool) {
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1], true
		}
	}
	return nil, false
}

func findOrCreateMap(parent *yaml.Node, key string) *yaml.Node {
	if node, ok := findMap(parent, key); ok {
		if node.Kind != yaml.MappingNode {
			node.Kind = yaml.MappingNode
			node.Tag = ""
			node.Value = ""
			node.Content = nil
		}
		return node
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	valueNode := &yaml.Node{Kind: yaml.MappingNode}
	parent.Content = append(parent.Content, keyNode, valueNode)
	return valueNode
}

func findSequence(parent *yaml.Node, key string) (*yaml.Node, bool) {
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1], true
		}
	}
	return nil, false
}

func findOrCreateSequence(parent *yaml.Node, key string) *yaml.Node {
	if node, ok := findSequence(parent, key); ok {
		if node.Kind != yaml.SequenceNode {
			node.Kind = yaml.SequenceNode
			node.Tag = ""
			node.Value = ""
			node.Content = nil
		}
		return node
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	valueNode := &yaml.Node{Kind: yaml.SequenceNode}
	parent.Content = append(parent.Content, keyNode, valueNode)
	return valueNode
}
