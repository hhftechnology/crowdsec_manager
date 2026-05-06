package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// TestMain initializes the logger so handler code that calls logger.Info/Error/Warn
// does not panic with a nil zap.Logger during tests.
func TestMain(m *testing.M) {
	logger.Init("error", "") // suppress output; only log errors during tests
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// fakeDockerClient is a test double for *docker.Client that records ExecCommand calls.
// It is safe to use from multiple goroutines.
type fakeDockerClient struct {
	mu      sync.Mutex
	calls   []fakeCall
	stubOut string
	stubErr error
	// perCall allows different responses per invocation index; falls back to stubOut/stubErr.
	perCall []fakeStub
}

type fakeCall struct {
	ContainerName string
	Cmd           []string
}

type fakeStub struct {
	out string
	err error
}

func (f *fakeDockerClient) ExecCommand(containerName string, cmd []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := len(f.calls)
	f.calls = append(f.calls, fakeCall{ContainerName: containerName, Cmd: cmd})
	if idx < len(f.perCall) {
		return f.perCall[idx].out, f.perCall[idx].err
	}
	return f.stubOut, f.stubErr
}

func (f *fakeDockerClient) recordedCalls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// newTestRouter sets up a minimal gin engine in test mode.
func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

// addDecisionWithFake builds a gin router wired to AddDecisionFake and issues a POST.
func addDecisionWithFake(t *testing.T, fake *fakeDockerClient, body string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}
	r := newTestRouter()
	r.POST("/decisions", AddDecisionFake(fake, cfg))
	req := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) models.Response {
	t.Helper()
	var resp models.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response body: %v — body: %s", err, w.Body.String())
	}
	return resp
}

// ---- Tests ----

func TestAddDecision_EmptyBody(t *testing.T) {
	fake := &fakeDockerClient{}
	w := addDecisionWithFake(t, fake, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
	calls := fake.recordedCalls()
	if len(calls) != 0 {
		t.Errorf("expected no ExecCommand calls on empty body, got %d", len(calls))
	}
}

func TestAddDecision_NoSelector(t *testing.T) {
	fake := &fakeDockerClient{}
	w := addDecisionWithFake(t, fake, `{"type":"ban","duration":"4h"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if !strings.Contains(resp.Error, ErrNoSelector.Error()) {
		t.Errorf("expected ErrNoSelector in error field, got: %q", resp.Error)
	}
	if len(fake.recordedCalls()) != 0 {
		t.Errorf("expected no ExecCommand calls, got %d", len(fake.recordedCalls()))
	}
}

func TestAddDecision_IPAndRange_MutuallyExclusive(t *testing.T) {
	fake := &fakeDockerClient{}
	w := addDecisionWithFake(t, fake, `{"ip":"1.2.3.4","range":"10.0.0.0/24","duration":"4h"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if !strings.Contains(resp.Error, ErrIPAndRange.Error()) {
		t.Errorf("expected ErrIPAndRange in error field, got: %q", resp.Error)
	}
	if len(fake.recordedCalls()) != 0 {
		t.Errorf("expected no ExecCommand calls, got %d", len(fake.recordedCalls()))
	}
}

func TestAddDecision_PermanentDuration_OmitsFlag(t *testing.T) {
	fake := &fakeDockerClient{stubOut: "Decision added", stubErr: nil}
	w := addDecisionWithFake(t, fake, `{"ip":"1.2.3.4","duration":"permanent"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	calls := fake.recordedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 ExecCommand call, got %d", len(calls))
	}
	cmd := calls[0].Cmd
	// --ip must be present
	if !containsSequence(cmd, "--ip", "1.2.3.4") {
		t.Errorf("expected --ip 1.2.3.4 in cmd %v", cmd)
	}
	// --duration must NOT be present
	for _, arg := range cmd {
		if arg == "--duration" {
			t.Errorf("--duration should be omitted for 'permanent', but cmd is %v", cmd)
		}
	}
}

func TestAddDecision_DurationNormalized(t *testing.T) {
	fake := &fakeDockerClient{stubOut: "Decision added", stubErr: nil}
	w := addDecisionWithFake(t, fake, `{"ip":"1.2.3.4","duration":"30d"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	calls := fake.recordedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 ExecCommand call, got %d", len(calls))
	}
	cmd := calls[0].Cmd
	if !containsSequence(cmd, "--duration", "720h") {
		t.Errorf("expected --duration 720h in cmd %v", cmd)
	}
}

func TestAddDecision_InvalidDuration_Returns400(t *testing.T) {
	fake := &fakeDockerClient{}
	w := addDecisionWithFake(t, fake, `{"ip":"1.2.3.4","duration":"garbage"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
	if len(fake.recordedCalls()) != 0 {
		t.Errorf("expected no ExecCommand calls, got %d", len(fake.recordedCalls()))
	}
}

func TestAddDecision_Success_Returns200WithOutput(t *testing.T) {
	fake := &fakeDockerClient{stubOut: "decision added successfully", stubErr: nil}
	w := addDecisionWithFake(t, fake, `{"ip":"1.2.3.4","duration":"4h","type":"ban"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if !resp.Success {
		t.Errorf("expected success=true, got false")
	}
	// Verify the output is surfaced in data
	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected Data to be map, got %T", resp.Data)
	}
	if dataMap["output"] != "decision added successfully" {
		t.Errorf("expected output in data, got %v", dataMap["output"])
	}
}

func TestAddDecision_ExecError_SurfacesDetails(t *testing.T) {
	fake := &fakeDockerClient{
		stubOut: "some stderr output",
		stubErr: errors.New("exit code 1"),
	}
	w := addDecisionWithFake(t, fake, `{"ip":"1.2.3.4","duration":"4h"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d — body: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if resp.Success {
		t.Errorf("expected success=false")
	}
	if resp.Error == "" {
		t.Errorf("expected error field to be set")
	}
	if resp.Details == "" {
		t.Errorf("expected details field to be set (should contain raw output/stderr)")
	}
}

// containsSequence checks whether slice contains flag followed immediately by value.
func containsSequence(slice []string, flag, value string) bool {
	for i := 0; i < len(slice)-1; i++ {
		if slice[i] == flag && slice[i+1] == value {
			return true
		}
	}
	return false
}

// AddDecisionFake is a test-only variant of AddDecision that accepts the
// cscliExecutor interface instead of *docker.Client, allowing injection of
// fakeDockerClient without needing a real Docker daemon.
// It lives here (not in production code) to keep the production handler clean.
func AddDecisionFake(executor interface {
	ExecCommand(containerName string, cmd []string) (string, error)
}, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req AddDecisionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request body: " + err.Error(),
			})
			return
		}

		// Validate selector fields
		if err := ValidateAddDecisionRequest(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		// Normalize duration
		normalized, ok := NormalizeDuration(req.Duration)
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "invalid duration: " + req.Duration,
			})
			return
		}

		cmd := []string{"cscli", "decisions", "add"}
		cmd, _ = appendCLIFlags(cmd, []CLIFlag{
			{"--ip", req.IP},
			{"--range", req.Range},
			{"--duration", normalized},
			{"--type", req.Type},
			{"--scope", req.Scope},
			{"--value", req.Value},
			{"--reason", req.Reason},
			{"--origin", req.Origin},
		})

		output, err := executor.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			details := output
			if details == "" {
				details = err.Error()
			}
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to add decision",
				Details: details,
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decision added successfully",
			Data:    gin.H{"output": output},
		})
	}
}

// Ensure fakeDockerClient satisfies the interface used by AddDecisionFake at compile time.
var _ interface {
	ExecCommand(string, []string) (string, error)
} = (*fakeDockerClient)(nil)
