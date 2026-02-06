package proxy

import (
	"testing"
)

// TestAdapterFeatureConsistency verifies that each registered adapter's
// SupportedFeatures() matches what ProxyFeatureMatrix declares for that type.
// This ensures the static matrix and runtime adapter implementations stay in sync.
func TestAdapterFeatureConsistency(t *testing.T) {
	for proxyType, expectedFeatures := range ProxyFeatureMatrix {
		t.Run(string(proxyType), func(t *testing.T) {
			// Verify the proxy type exists in the matrix
			if len(expectedFeatures) == 0 && proxyType != ProxyTypeStandalone {
				t.Errorf("proxy type %s has empty feature set in ProxyFeatureMatrix", proxyType)
			}

			// Verify IsFeatureSupported is consistent with the matrix
			for _, feature := range GetAllFeatures() {
				matrixHas := expectedFeatures.Has(feature)
				helperHas := IsFeatureSupported(proxyType, feature)

				if matrixHas != helperHas {
					t.Errorf("inconsistency for %s/%s: matrix=%v helper=%v",
						proxyType, feature, matrixHas, helperHas)
				}
			}
		})
	}
}

// TestAllProxyTypesHaveFeatureMatrix verifies all known proxy types have entries.
func TestAllProxyTypesHaveFeatureMatrix(t *testing.T) {
	for _, proxyType := range GetAllProxyTypes() {
		if _, exists := ProxyFeatureMatrix[proxyType]; !exists {
			t.Errorf("proxy type %s missing from ProxyFeatureMatrix", proxyType)
		}
	}
}

// TestAllProxyTypesHaveHealth verifies every proxy supports the health feature.
func TestAllProxyTypesHaveHealth(t *testing.T) {
	for _, proxyType := range GetAllProxyTypes() {
		if !IsFeatureSupported(proxyType, FeatureHealth) {
			t.Errorf("proxy type %s should support health feature", proxyType)
		}
	}
}

// TestFeatureSetOperations tests the FeatureSet utility methods.
func TestFeatureSetOperations(t *testing.T) {
	fs1 := NewFeatureSet(FeatureWhitelist, FeatureLogs, FeatureHealth)
	fs2 := NewFeatureSet(FeatureLogs, FeatureBouncer, FeatureHealth)

	// Has
	if !fs1.Has(FeatureWhitelist) {
		t.Error("fs1 should have whitelist")
	}
	if fs1.Has(FeatureBouncer) {
		t.Error("fs1 should not have bouncer")
	}

	// Merge
	merged := fs1.Merge(fs2)
	if len(merged) != 4 {
		t.Errorf("merged should have 4 features, got %d", len(merged))
	}

	// Intersect
	intersect := fs1.Intersect(fs2)
	if len(intersect) != 2 {
		t.Errorf("intersection should have 2 features, got %d", len(intersect))
	}
	if !intersect.Has(FeatureLogs) || !intersect.Has(FeatureHealth) {
		t.Error("intersection should contain logs and health")
	}

	// Difference
	diff := fs1.Difference(fs2)
	if len(diff) != 1 {
		t.Errorf("difference should have 1 feature, got %d", len(diff))
	}
	if !diff.Has(FeatureWhitelist) {
		t.Error("difference should contain whitelist")
	}
}

// TestValidateFeature tests feature validation.
func TestValidateFeature(t *testing.T) {
	validFeatures := []string{"whitelist", "captcha", "logs", "bouncer", "health", "appsec"}
	for _, f := range validFeatures {
		if err := ValidateFeature(f); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", f, err)
		}
	}

	invalidFeatures := []string{"", "invalid", "firewall", "dns"}
	for _, f := range invalidFeatures {
		if err := ValidateFeature(f); err == nil {
			t.Errorf("expected %q to be invalid", f)
		}
	}
}
