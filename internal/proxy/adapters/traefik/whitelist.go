package traefik

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
	"gopkg.in/yaml.v3"
)

// WhitelistMgr manages the Traefik ipAllowList middleware configuration.
type WhitelistMgr struct {
	docker *docker.Client
	cfg    *config.Config
	paths  config.ProxyPaths
}

// traefikDynamicConfig is used for reading/writing the dynamic YAML.
type traefikDynamicConfig struct {
	HTTP struct {
		Middlewares map[string]interface{} `yaml:"middlewares,omitempty"`
	} `yaml:"http"`
}

func (m *WhitelistMgr) List(ctx context.Context) ([]proxy.WhitelistEntry, error) {
	ips, err := m.readSourceRange(ctx)
	if err != nil {
		return nil, err
	}

	entries := make([]proxy.WhitelistEntry, 0, len(ips))
	for _, ip := range ips {
		entries = append(entries, proxy.WhitelistEntry{
			IP:     ip,
			Source: "traefik",
		})
	}
	return entries, nil
}

func (m *WhitelistMgr) Add(ctx context.Context, entry proxy.WhitelistEntry) error {
	ips, err := m.readSourceRange(ctx)
	if err != nil {
		return err
	}

	// Check for duplicates.
	for _, existing := range ips {
		if existing == entry.IP {
			return nil
		}
	}

	entry.AddedAt = time.Now().UTC().Format(time.RFC3339)
	ips = append(ips, entry.IP)
	return m.writeSourceRange(ctx, ips)
}

func (m *WhitelistMgr) Remove(ctx context.Context, ip string) error {
	ips, err := m.readSourceRange(ctx)
	if err != nil {
		return err
	}

	filtered := make([]string, 0, len(ips))
	for _, existing := range ips {
		if existing != ip {
			filtered = append(filtered, existing)
		}
	}

	return m.writeSourceRange(ctx, filtered)
}

func (m *WhitelistMgr) readSourceRange(ctx context.Context) ([]string, error) {
	data, err := m.docker.ReadFileFromContainer(ctx, m.cfg.ProxyContainer, m.paths.DynamicConfig)
	if err != nil {
		return nil, fmt.Errorf("read dynamic config: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse dynamic config YAML: %w", err)
	}

	// Navigate: http -> middlewares -> crowdsec-whitelist -> ipAllowList -> sourceRange
	ips, _ := extractSourceRange(&doc)
	return ips, nil
}

func (m *WhitelistMgr) writeSourceRange(ctx context.Context, ips []string) error {
	data, err := m.docker.ReadFileFromContainer(ctx, m.cfg.ProxyContainer, m.paths.DynamicConfig)
	if err != nil {
		// If file doesn't exist, create a new one.
		data = []byte("{}")
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse dynamic config: %w", err)
	}

	setSourceRange(&doc, ips)

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("marshal dynamic config: %w", err)
	}

	return m.docker.WriteFileToContainer(ctx, m.cfg.ProxyContainer, m.paths.DynamicConfig, out)
}

// extractSourceRange walks the YAML node tree to find sourceRange values.
func extractSourceRange(doc *yaml.Node) ([]string, bool) {
	if doc == nil || len(doc.Content) == 0 {
		return nil, false
	}
	root := doc.Content[0]

	httpNode := findMapValue(root, "http")
	if httpNode == nil {
		return nil, false
	}
	mwNode := findMapValue(httpNode, "middlewares")
	if mwNode == nil {
		return nil, false
	}
	wlNode := findMapValue(mwNode, "crowdsec-whitelist")
	if wlNode == nil {
		return nil, false
	}
	allowNode := findMapValue(wlNode, "ipAllowList")
	if allowNode == nil {
		return nil, false
	}
	srNode := findMapValue(allowNode, "sourceRange")
	if srNode == nil || srNode.Kind != yaml.SequenceNode {
		return nil, false
	}

	ips := make([]string, 0, len(srNode.Content))
	for _, n := range srNode.Content {
		ips = append(ips, n.Value)
	}
	return ips, true
}

// setSourceRange updates or creates the sourceRange in the YAML tree.
func setSourceRange(doc *yaml.Node, ips []string) {
	if doc == nil || len(doc.Content) == 0 {
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	root := doc.Content[0]

	httpNode := findOrCreateMap(root, "http")
	mwNode := findOrCreateMap(httpNode, "middlewares")
	wlNode := findOrCreateMap(mwNode, "crowdsec-whitelist")
	allowNode := findOrCreateMap(wlNode, "ipAllowList")

	// Build the sourceRange sequence.
	seqNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, ip := range ips {
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: ip,
			Tag:   "!!str",
		})
	}

	setMapValue(allowNode, "sourceRange", seqNode)
}

func findMapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func findOrCreateMap(parent *yaml.Node, key string) *yaml.Node {
	if parent.Kind != yaml.MappingNode {
		parent.Kind = yaml.MappingNode
		parent.Tag = "!!map"
	}
	for i := 0; i < len(parent.Content)-1; i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}
	// Create the key and an empty mapping value.
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode
}

func setMapValue(parent *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i < len(parent.Content)-1; i += 2 {
		if parent.Content[i].Value == key {
			parent.Content[i+1] = value
			return
		}
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
		value,
	)
}
