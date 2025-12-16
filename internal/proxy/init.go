package proxy

import (
	"log"
)

// InitializeAdapters registers all available proxy adapters with the global registry
// Note: Adapters are now registered in main.go to avoid import cycles
func InitializeAdapters() error {
	log.Printf("Registered proxy adapters: %v", GetRegisteredAdapterTypes())
	return nil
}

// MustInitializeAdapters initializes adapters and panics on error
func MustInitializeAdapters() {
	if err := InitializeAdapters(); err != nil {
		panic("Failed to initialize proxy adapters: " + err.Error())
	}
}