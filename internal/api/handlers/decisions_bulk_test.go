package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// bulkDeleteWithFake issues a POST /decisions/bulk-delete with the given body,
// using the provided fakeDockerClient.
func bulkDeleteWithFake(t *testing.T, fake *fakeDockerClient, body string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/decisions/bulk-delete", BulkDeleteDecisions(fake, cfg))
	req := httptest.NewRequest(http.MethodPost, "/decisions/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeBulkResponse(t *testing.T, w *httptest.ResponseRecorder) (models.Response, BulkDeleteResult) {
	t.Helper()
	var resp models.Response
	if err := json.NewDecoder(strings.NewReader(w.Body.String())).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v — body: %s", err, w.Body.String())
	}
	// Re-decode data portion as BulkDeleteResult
	dataBytes, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("failed to marshal data: %v", err)
	}
	var result BulkDeleteResult
	if err := json.Unmarshal(dataBytes, &result); err != nil {
		t.Fatalf("failed to unmarshal BulkDeleteResult: %v", err)
	}
	return resp, result
}

func TestBulkDeleteDecisions_EmptyIDs(t *testing.T) {
	fake := &fakeDockerClient{}
	w := bulkDeleteWithFake(t, fake, `{"ids":[]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
	if len(fake.recordedCalls()) != 0 {
		t.Errorf("expected no ExecCommand calls, got %d", len(fake.recordedCalls()))
	}
}

func TestBulkDeleteDecisions_MissingBody(t *testing.T) {
	fake := &fakeDockerClient{}
	w := bulkDeleteWithFake(t, fake, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestBulkDeleteDecisions_AllSucceed(t *testing.T) {
	fake := &fakeDockerClient{stubOut: "Decision deleted", stubErr: nil}
	w := bulkDeleteWithFake(t, fake, `{"ids":[12,34,56]}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	resp, result := decodeBulkResponse(t, w)
	if !resp.Success {
		t.Errorf("expected success=true")
	}
	if result.SuccessCount != 3 {
		t.Errorf("expected success_count=3, got %d", result.SuccessCount)
	}
	if result.FailureCount != 0 {
		t.Errorf("expected failure_count=0, got %d", result.FailureCount)
	}
	if len(result.Deleted) != 3 {
		t.Errorf("expected 3 deleted ids, got %v", result.Deleted)
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected no failed, got %v", result.Failed)
	}
	// Verify each call used --id <n>
	calls := fake.recordedCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 ExecCommand calls, got %d", len(calls))
	}
	for i, id := range []string{"12", "34", "56"} {
		if !containsSequence(calls[i].Cmd, "--id", id) {
			t.Errorf("call %d: expected --id %s in cmd %v", i, id, calls[i].Cmd)
		}
	}
}

func TestBulkDeleteDecisions_DeduplicatesIDs(t *testing.T) {
	fake := &fakeDockerClient{stubOut: "Decision deleted", stubErr: nil}
	w := bulkDeleteWithFake(t, fake, `{"ids":[12,12,34,12]}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	_, result := decodeBulkResponse(t, w)
	if result.SuccessCount != 2 {
		t.Errorf("expected success_count=2 for unique ids, got %d", result.SuccessCount)
	}
	if result.FailureCount != 0 {
		t.Errorf("expected failure_count=0, got %d", result.FailureCount)
	}
	if len(result.Deleted) != 2 || result.Deleted[0] != 12 || result.Deleted[1] != 34 {
		t.Errorf("expected deleted ids [12 34], got %v", result.Deleted)
	}

	calls := fake.recordedCalls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 ExecCommand calls, got %d", len(calls))
	}
	for i, id := range []string{"12", "34"} {
		if !containsSequence(calls[i].Cmd, "--id", id) {
			t.Errorf("call %d: expected --id %s in cmd %v", i, id, calls[i].Cmd)
		}
	}
}

func TestBulkDeleteDecisions_RejectsMoreThanMaximumUniqueIDs(t *testing.T) {
	ids := make([]string, maxBulkDeleteDecisionIDs+1)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	body := `{"ids":[` + strings.Join(ids, ",") + `]}`

	fake := &fakeDockerClient{}
	w := bulkDeleteWithFake(t, fake, body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
	if len(fake.recordedCalls()) != 0 {
		t.Errorf("expected no ExecCommand calls, got %d", len(fake.recordedCalls()))
	}
}

func TestBulkDeleteDecisions_PartialFailure(t *testing.T) {
	// ID 34 (second call, index 1) fails; 12 and 56 succeed.
	fake := &fakeDockerClient{
		perCall: []fakeStub{
			{out: "Decision deleted", err: nil},
			{out: "stderr error", err: errors.New("exit code 1")},
			{out: "Decision deleted", err: nil},
		},
	}
	w := bulkDeleteWithFake(t, fake, `{"ids":[12,34,56]}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (partial failure still 200), got %d — body: %s", w.Code, w.Body.String())
	}
	resp, result := decodeBulkResponse(t, w)
	if !resp.Success {
		t.Errorf("expected success=true (partial success is still successful response)")
	}
	if result.SuccessCount != 2 {
		t.Errorf("expected success_count=2, got %d", result.SuccessCount)
	}
	if result.FailureCount != 1 {
		t.Errorf("expected failure_count=1, got %d", result.FailureCount)
	}
	if len(result.Deleted) != 2 {
		t.Errorf("expected 2 deleted ids, got %v", result.Deleted)
	}
	if len(result.Failed) != 1 {
		t.Fatalf("expected 1 failed entry, got %v", result.Failed)
	}
	if result.Failed[0].ID != 34 {
		t.Errorf("expected failed id=34, got %d", result.Failed[0].ID)
	}
	if result.Failed[0].Error == "" {
		t.Errorf("expected non-empty error in failed entry")
	}
}
