package proxy

import "fmt"

// FeatureSet represents a collection of supported features
type FeatureSet map[Feature]bool

// NewFeatureSet creates a new feature set from a list of features
func NewFeatureSet(features ...Feature) FeatureSet {
	fs := make(FeatureSet)
	for _, feature := range features {
		fs[feature] = true
	}
	return fs
}

// Has checks if a feature is supported
func (fs FeatureSet) Has(feature Feature) bool {
	return fs[feature]
}

// List returns all supported features as a slice
func (fs FeatureSet) List() []Feature {
	features := make([]Feature, 0, len(fs))
	for feature := range fs {
		features = append(features, feature)
	}
	return features
}

// Strings returns all supported features as string slice
func (fs FeatureSet) Strings() []string {
	features := make([]string, 0, len(fs))
	for feature := range fs {
		features = append(features, string(feature))
	}
	return features
}

// Add adds a feature to the set
func (fs FeatureSet) Add(feature Feature) {
	fs[feature] = true
}

// Remove removes a feature from the set
func (fs FeatureSet) Remove(feature Feature) {
	delete(fs, feature)
}

// Merge combines this feature set with another
func (fs FeatureSet) Merge(other FeatureSet) FeatureSet {
	merged := make(FeatureSet)
	for feature := range fs {
		merged[feature] = true
	}
	for feature := range other {
		merged[feature] = true
	}
	return merged
}

// Intersect returns features common to both sets
func (fs FeatureSet) Intersect(other FeatureSet) FeatureSet {
	intersection := make(FeatureSet)
	for feature := range fs {
		if other.Has(feature) {
			intersection[feature] = true
		}
	}
	return intersection
}

// Difference returns features in this set but not in the other
func (fs FeatureSet) Difference(other FeatureSet) FeatureSet {
	diff := make(FeatureSet)
	for feature := range fs {
		if !other.Has(feature) {
			diff[feature] = true
		}
	}
	return diff
}

// String returns a human-readable representation of the feature set
func (fs FeatureSet) String() string {
	if len(fs) == 0 {
		return "no features"
	}
	
	features := fs.Strings()
	if len(features) == 1 {
		return features[0]
	}
	
	result := ""
	for i, feature := range features {
		if i == 0 {
			result = feature
		} else if i == len(features)-1 {
			result += " and " + feature
		} else {
			result += ", " + feature
		}
	}
	return result
}

// ValidateFeature checks if a feature string is valid
func ValidateFeature(feature string) error {
	switch Feature(feature) {
	case FeatureWhitelist, FeatureCaptcha, FeatureLogs, FeatureBouncer, FeatureHealth, FeatureAppSec:
		return nil
	default:
		return fmt.Errorf("invalid feature: %s", feature)
	}
}

// GetAllFeatures returns all available features
func GetAllFeatures() []Feature {
	return []Feature{
		FeatureWhitelist,
		FeatureCaptcha,
		FeatureLogs,
		FeatureBouncer,
		FeatureHealth,
		FeatureAppSec,
	}
}

// GetFeatureDescription returns a human-readable description of a feature
func GetFeatureDescription(feature Feature) string {
	descriptions := map[Feature]string{
		FeatureWhitelist: "IP and CIDR whitelist management at the proxy level",
		FeatureCaptcha:   "Captcha protection configuration and management",
		FeatureLogs:      "Access log parsing and analysis capabilities",
		FeatureBouncer:   "CrowdSec bouncer integration and status monitoring",
		FeatureHealth:    "Proxy health monitoring and diagnostics",
		FeatureAppSec:    "Application security features and WAF capabilities",
	}
	
	if desc, exists := descriptions[feature]; exists {
		return desc
	}
	return fmt.Sprintf("Unknown feature: %s", feature)
}

// ProxyFeatureMatrix defines which features are supported by each proxy type
var ProxyFeatureMatrix = map[ProxyType]FeatureSet{
	ProxyTypeTraefik: NewFeatureSet(
		FeatureWhitelist,
		FeatureCaptcha,
		FeatureLogs,
		FeatureBouncer,
		FeatureHealth,
		FeatureAppSec,
	),
	ProxyTypeNginx: NewFeatureSet(
		FeatureLogs,
		FeatureBouncer,
		FeatureHealth,
	),
	ProxyTypeCaddy: NewFeatureSet(
		FeatureBouncer,
		FeatureHealth,
	),
	ProxyTypeHAProxy: NewFeatureSet(
		FeatureBouncer,
		FeatureHealth,
	),
	ProxyTypeZoraxy: NewFeatureSet(
		FeatureHealth,
	),
	ProxyTypeStandalone: NewFeatureSet(
		FeatureHealth,
	),
}

// GetSupportedFeatures returns the features supported by a proxy type
func GetSupportedFeatures(proxyType ProxyType) FeatureSet {
	if features, exists := ProxyFeatureMatrix[proxyType]; exists {
		return features
	}
	return NewFeatureSet() // Empty set for unknown proxy types
}

// IsFeatureSupported checks if a specific feature is supported by a proxy type
func IsFeatureSupported(proxyType ProxyType, feature Feature) bool {
	return GetSupportedFeatures(proxyType).Has(feature)
}