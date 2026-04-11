package handlers

import "crowdsec-manager/internal/history"

var historyService *history.Service

// SetHistoryService sets the package-level history service for history APIs/hooks.
func SetHistoryService(s *history.Service) {
	historyService = s
}
