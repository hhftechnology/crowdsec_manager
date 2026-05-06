package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// fakeHistoryService is a minimal stub that satisfies the historyService interface
// for the parts needed by ReapplyDecision tests.
type fakeHistoryRecord struct {
	record *models.DecisionHistoryRecord
	err    error
}

// ---- IsDecisionActive tests ----

func TestIsDecisionActive_Active(t *testing.T) {
	// cscli decisions list -o json returns a JSON array with a matching decision
	activeJSON := `[{"id":42,"scope":"Ip","value":"1.2.3.4","type":"ban","origin":"cscli","duration":"24h"}]`
	fake := &fakeDockerClient{stubOut: activeJSON, stubErr: nil}
	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}

	id, active, err := IsDecisionActive(fake, cfg, "Ip", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !active {
		t.Errorf("expected active=true for existing decision")
	}
	if id != 42 {
		t.Errorf("expected id=42, got %d", id)
	}

	// Verify the command called cscli decisions list with correct flags
	calls := fake.recordedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 ExecCommand call, got %d", len(calls))
	}
	cmd := calls[0].Cmd
	if !containsSequence(cmd, "--scope", "Ip") {
		t.Errorf("expected --scope Ip in cmd %v", cmd)
	}
	if !containsSequence(cmd, "--value", "1.2.3.4") {
		t.Errorf("expected --value 1.2.3.4 in cmd %v", cmd)
	}
}

func TestIsDecisionActive_Empty(t *testing.T) {
	// cscli returns null or empty array when no matching decision
	for _, out := range []string{"null", "[]", ""} {
		t.Run(fmt.Sprintf("output=%q", out), func(t *testing.T) {
			fake := &fakeDockerClient{stubOut: out, stubErr: nil}
			cfg := &config.Config{CrowdsecContainerName: "crowdsec"}

			_, active, err := IsDecisionActive(fake, cfg, "Ip", "1.2.3.4")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if active {
				t.Errorf("expected active=false for empty output %q", out)
			}
		})
	}
}

func TestIsDecisionActive_ExecError(t *testing.T) {
	fake := &fakeDockerClient{stubOut: "", stubErr: fmt.Errorf("container not found")}
	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}

	_, _, err := IsDecisionActive(fake, cfg, "Ip", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error when exec fails")
	}
}

// ---- ReapplyDecision idempotency tests ----

func TestReapplyDecisionFake_AlreadyActive(t *testing.T) {
	// First call: cscli decisions list → returns active decision
	// Second call: cscli decisions add → should NOT be called
	activeJSON := `[{"id":99,"scope":"Ip","value":"5.6.7.8","type":"ban","origin":"cscli","duration":"24h"}]`
	fake := &fakeDockerClient{
		perCall: []fakeStub{
			{out: activeJSON, err: nil}, // list call
			// no add call should happen
		},
	}

	record := &models.DecisionHistoryRecord{
		ID: 1, Scope: "Ip", Value: "5.6.7.8",
	}
	w := reapplyDecisionWithFakeRecord(t, fake, record, `{"id":1,"type":"ban","duration":"24h"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp models.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success=true")
	}
	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected Data to be map, got %T", resp.Data)
	}
	if dataMap["already_active"] != true {
		t.Errorf("expected already_active=true, got %v", dataMap["already_active"])
	}

	// Ensure only ONE exec call (the list call), not two (no add call)
	calls := fake.recordedCalls()
	if len(calls) != 1 {
		t.Errorf("expected 1 ExecCommand call (list only), got %d: %v", len(calls), calls)
	}
}

func TestReapplyDecisionFake_NotActive_Proceeds(t *testing.T) {
	// First call: cscli decisions list → returns empty (not active)
	// Second call: cscli decisions add → should be called
	fake := &fakeDockerClient{
		perCall: []fakeStub{
			{out: "null", err: nil},              // list call → not active
			{out: "Decision added", err: nil},     // add call
		},
	}

	record := &models.DecisionHistoryRecord{
		ID: 2, Scope: "Ip", Value: "9.10.11.12",
	}
	w := reapplyDecisionWithFakeRecord(t, fake, record, `{"id":2,"type":"ban","duration":"24h"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp models.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success=true")
	}

	// Ensure TWO exec calls (list + add)
	calls := fake.recordedCalls()
	if len(calls) != 2 {
		t.Errorf("expected 2 ExecCommand calls (list + add), got %d: %v", len(calls), calls)
	}
	// Second call must be a decisions add
	addCmd := calls[1].Cmd
	if len(addCmd) < 3 || addCmd[1] != "decisions" || addCmd[2] != "add" {
		t.Errorf("second call should be 'cscli decisions add', got %v", addCmd)
	}

	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected Data to be map, got %T", resp.Data)
	}
	if dataMap["already_active"] != false {
		t.Errorf("expected already_active=false, got %v", dataMap["already_active"])
	}
}

// reapplyDecisionWithFakeRecord is a test handler that uses a fake executor and
// a stubbed history record instead of the real historyService.
func reapplyDecisionWithFakeRecord(t *testing.T, fakeExec *fakeDockerClient, record *models.DecisionHistoryRecord, body string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/reapply", ReapplyDecisionWithExecutorAndRecord(fakeExec, cfg, record))
	req := httptest.NewRequest(http.MethodPost, "/reapply", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
