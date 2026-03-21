package scanner

import (
	"sync"
)

// Resource represents a single cloud resource.
type Resource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Category string `json:"category"`
	Region   string `json:"region"`
	State    string `json:"state"`
	Detail   string `json:"detail"`
	Billable bool   `json:"billable"`
	Cloud    string `json:"cloud"`
}

// LogEntry is a timestamped log message with a severity level.
type LogEntry struct {
	TS  string `json:"ts"`
	Msg string `json:"msg"`
	Lvl string `json:"lvl"` // "info", "ok", "err", "warn", "dim", "section"
}

// CloudStatus tracks per-cloud scan progress.
type CloudStatus struct {
	Status string `json:"status"` // "pending", "scanning", "done", "error"
	Count  int    `json:"count"`
	Error  string `json:"error"`
}

// ScanState holds all state for a running or completed scan.
// The mu field is unexported so it is ignored by json.Marshal.
type ScanState struct {
	mu sync.RWMutex

	ID             string                  `json:"id"`
	Clouds         []string                `json:"clouds"`
	Mode           string                  `json:"mode"`
	Status         string                  `json:"status"` // "queued", "running", "complete"
	Progress       string                  `json:"progress"`
	CreatedAt      string                  `json:"created_at"`
	StartedAt      string                  `json:"started_at,omitempty"`
	CompletedAt    string                  `json:"completed_at,omitempty"`
	CloudStatus    map[string]*CloudStatus `json:"cloud_status"`
	CurrentCloud   *string                 `json:"current_cloud"`
	ResourcesSoFar int                     `json:"resources_so_far"`
	StepsDone      int                     `json:"steps_done"`
	StepsTotal     int                     `json:"steps_total"`
	Resources      []Resource              `json:"resources"`
	Summary        map[string]any          `json:"summary"`
	Errors         []string                `json:"errors"`
	Log            []LogEntry              `json:"log"`
}

func (s *ScanState) Lock()    { s.mu.Lock() }
func (s *ScanState) Unlock()  { s.mu.Unlock() }
func (s *ScanState) RLock()   { s.mu.RLock() }
func (s *ScanState) RUnlock() { s.mu.RUnlock() }

// AddLog appends a log entry and caps the log to 2000 entries.
func (s *ScanState) AddLog(ts, msg, lvl string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Log = append(s.Log, LogEntry{TS: ts, Msg: msg, Lvl: lvl})
	if len(s.Log) > 2000 {
		s.Log = s.Log[200:]
	}
}

// AddResources appends resources and updates ResourcesSoFar.
func (s *ScanState) AddResources(resources []Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Resources = append(s.Resources, resources...)
	s.ResourcesSoFar = len(s.Resources)
}
