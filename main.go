// AccuKnox Asset Check — Multi-Cloud Asset Inventory & Billability Tool
// Go rewrite: single static binary, ~15–30 MB, instant start.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/accuknox/ak-asset-check/scanner"
	awsscanner    "github.com/accuknox/ak-asset-check/scanner/aws"
	azurescanner  "github.com/accuknox/ak-asset-check/scanner/azure"
	gcpscanner    "github.com/accuknox/ak-asset-check/scanner/gcp"
	oraclescanner "github.com/accuknox/ak-asset-check/scanner/oracle"
)

//go:embed static
var staticFS embed.FS

//go:embed aws-billable-assets.txt azure-billable-assets.txt gcp-billable-assets.txt oracle-billable-assets.txt
var billableFS embed.FS

// buildDate is injected at link time via -ldflags "-X main.buildDate=..."
var buildDate = "unknown"

var (
	scans   = make(map[string]*scanner.ScanState)
	scansmu sync.RWMutex

	awsBillable    map[string]bool
	azureBillable  map[string]bool
	gcpBillable    map[string]bool
	oracleBillable map[string]bool
)

func init() {
	awsBillable    = scanner.LoadBillableTypes(billableFS, "aws-billable-assets.txt", scanner.KeywordToAWSTypes())
	azureBillable  = scanner.LoadBillableTypes(billableFS, "azure-billable-assets.txt", scanner.KeywordToAzureTypes())
	gcpBillable    = scanner.LoadBillableTypes(billableFS, "gcp-billable-assets.txt", scanner.KeywordToGCPTypes())
	oracleBillable = scanner.LoadBillableTypes(billableFS, "oracle-billable-assets.txt", scanner.KeywordToOracleTypes())
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	sub, _ := fs.Sub(staticFS, "static")

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/", serveIndex)
	r.Get("/favicon.ico", serveFavicon)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))

	r.Get("/api/clouds", handleClouds)
	r.Get("/api/readonly-check", handleReadonlyCheck)
	r.Post("/api/scan", handleStartScan)
	r.Get("/api/scan/{id}", handleGetScan)
	r.Get("/api/scan/{id}/log", handleGetScanLog)
	r.Get("/api/scans", handleListScans)

	fmt.Printf("AccuKnox Asset Check — built %s — http://0.0.0.0:%s\n", buildDate, port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ── Static file handlers ──────────────────────────────────────────────────────

func serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func serveFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/favicon.ico")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Write(data)
}

// ── API handlers ──────────────────────────────────────────────────────────────

// handleClouds returns cloud configuration status for all providers.
func handleClouds(w http.ResponseWriter, r *http.Request) {
	awsOk, awsLabel := awsscanner.Detect()
	azOk, azLabel   := azurescanner.Detect()
	gcpOk, gcpLabel := gcpscanner.Detect()
	ociOk, ociLabel := oraclescanner.Detect()

	jsonResponse(w, map[string]any{
		"aws":    map[string]any{"configured": awsOk, "label": awsLabel},
		"azure":  map[string]any{"configured": azOk, "label": azLabel},
		"gcp":    map[string]any{"configured": gcpOk, "label": gcpLabel},
		"oracle": map[string]any{"configured": ociOk, "label": ociLabel},
	})
}

// handleReadonlyCheck returns read-only credential status for all configured clouds.
func handleReadonlyCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	notCfg := map[string]any{
		"readonly": nil, "enforced": false,
		"warning": "Not configured", "method": "none",
	}

	result := map[string]any{}

	if ok, _ := awsscanner.Detect(); ok {
		result["aws"] = awsscanner.CheckReadOnly(ctx)
	} else {
		result["aws"] = notCfg
	}
	if ok, _ := azurescanner.Detect(); ok {
		result["azure"] = azurescanner.CheckReadOnly(ctx)
	} else {
		result["azure"] = notCfg
	}
	if ok, _ := gcpscanner.Detect(); ok {
		result["gcp"] = gcpscanner.CheckReadOnly(ctx)
	} else {
		result["gcp"] = notCfg
	}
	if ok, _ := oraclescanner.Detect(); ok {
		result["oracle"] = oraclescanner.CheckReadOnly(ctx)
	} else {
		result["oracle"] = notCfg
	}

	jsonResponse(w, result)
}

// handleStartScan starts an asynchronous scan.
// Query params: clouds (comma-separated), mode (billable|full)
func handleStartScan(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode != "billable" && mode != "full" {
		mode = "billable"
	}

	cloudsParam := r.URL.Query().Get("clouds")
	if cloudsParam == "" {
		cloudsParam = "aws"
	}

	valid := map[string]bool{"aws": true, "azure": true, "gcp": true, "oracle": true}
	seen  := map[string]bool{}
	var cloudList []string
	for _, c := range strings.Split(cloudsParam, ",") {
		c = strings.TrimSpace(strings.ToLower(c))
		if valid[c] && !seen[c] {
			cloudList = append(cloudList, c)
			seen[c] = true
		}
	}
	if len(cloudList) == 0 {
		cloudList = []string{"aws"}
	}

	scanID      := uuid.New().String()
	cloudStatus := make(map[string]*scanner.CloudStatus, len(cloudList))
	for _, c := range cloudList {
		cloudStatus[c] = &scanner.CloudStatus{Status: "pending"}
	}

	state := &scanner.ScanState{
		ID:          scanID,
		Clouds:      cloudList,
		Mode:        mode,
		Status:      "queued",
		Progress:    "Starting...",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		CloudStatus: cloudStatus,
		StepsTotal:  len(cloudList),
		Resources:   []scanner.Resource{},
		Summary:     map[string]any{},
		Errors:      []string{},
		Log:         []scanner.LogEntry{},
	}

	scansmu.Lock()
	scans[scanID] = state
	scansmu.Unlock()

	go runScan(scanID)

	jsonResponse(w, map[string]string{"scan_id": scanID})
}

// handleGetScan returns the full scan state including resources.
func handleGetScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	scansmu.RLock()
	state, ok := scans[scanID]
	scansmu.RUnlock()
	if !ok {
		http.Error(w, `{"detail":"Scan not found"}`, http.StatusNotFound)
		return
	}
	state.RLock()
	defer state.RUnlock()
	jsonResponse(w, state)
}

// handleGetScanLog returns paginated log entries for a scan.
func handleGetScanLog(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	scansmu.RLock()
	state, ok := scans[scanID]
	scansmu.RUnlock()
	if !ok {
		http.Error(w, `{"detail":"Scan not found"}`, http.StatusNotFound)
		return
	}

	var offset int
	fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &offset)

	state.RLock()
	total := len(state.Log)
	var entries []scanner.LogEntry
	if offset < total {
		entries = state.Log[offset:]
	} else {
		entries = []scanner.LogEntry{}
	}
	state.RUnlock()

	jsonResponse(w, map[string]any{"entries": entries, "total": total})
}

// scanStateNoResources is a view of ScanState without the Resources slice.
type scanStateNoResources struct {
	ID             string                          `json:"id"`
	Clouds         []string                        `json:"clouds"`
	Mode           string                          `json:"mode"`
	Status         string                          `json:"status"`
	Progress       string                          `json:"progress"`
	CreatedAt      string                          `json:"created_at"`
	StartedAt      string                          `json:"started_at,omitempty"`
	CompletedAt    string                          `json:"completed_at,omitempty"`
	CloudStatus    map[string]*scanner.CloudStatus `json:"cloud_status"`
	CurrentCloud   *string                         `json:"current_cloud"`
	ResourcesSoFar int                             `json:"resources_so_far"`
	StepsDone      int                             `json:"steps_done"`
	StepsTotal     int                             `json:"steps_total"`
	Summary        map[string]any                  `json:"summary"`
	Errors         []string                        `json:"errors"`
}

// handleListScans returns all scans without resource details.
func handleListScans(w http.ResponseWriter, r *http.Request) {
	scansmu.RLock()
	defer scansmu.RUnlock()

	result := make([]scanStateNoResources, 0, len(scans))
	for _, s := range scans {
		s.RLock()
		v := scanStateNoResources{
			ID:             s.ID,
			Clouds:         s.Clouds,
			Mode:           s.Mode,
			Status:         s.Status,
			Progress:       s.Progress,
			CreatedAt:      s.CreatedAt,
			StartedAt:      s.StartedAt,
			CompletedAt:    s.CompletedAt,
			CloudStatus:    s.CloudStatus,
			CurrentCloud:   s.CurrentCloud,
			ResourcesSoFar: s.ResourcesSoFar,
			StepsDone:      s.StepsDone,
			StepsTotal:     s.StepsTotal,
			Summary:        s.Summary,
			Errors:         s.Errors,
		}
		s.RUnlock()
		result = append(result, v)
	}
	jsonResponse(w, result)
}

// ── Scan orchestration ────────────────────────────────────────────────────────

func ts() string { return time.Now().Format("15:04:05") }

// runScan orchestrates a multi-cloud scan, running each cloud in its own goroutine.
func runScan(scanID string) {
	scansmu.RLock()
	state := scans[scanID]
	scansmu.RUnlock()

	ctx := context.Background()

	state.Lock()
	state.Status = "running"
	state.StartedAt = time.Now().UTC().Format(time.RFC3339)
	state.Unlock()

	clouds := state.Clouds
	mode   := state.Mode

	state.AddLog(ts(), fmt.Sprintf("Scan started — clouds: %s, mode: %s",
		strings.ToUpper(strings.Join(clouds, ", ")), mode), "info")

	var wg sync.WaitGroup

	for _, cloud := range clouds {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()

			state.Lock()
			state.CloudStatus[c].Status = "scanning"
			state.Progress = fmt.Sprintf("Scanning %s…", strings.ToUpper(c))
			state.Unlock()

			state.AddLog(ts(),
				fmt.Sprintf("── %s ──────────────────────────────", strings.ToUpper(c)),
				"section")

			var scanErr error
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						scanErr = fmt.Errorf("panic: %v", rec)
					}
				}()

				switch c {
				case "aws":
					if ro := awsscanner.CheckReadOnly(ctx); ro["readonly"] == false {
						if w, ok := ro["warning"].(string); ok && w != "" {
							state.AddLog(ts(), "⚠ SECURITY: "+w, "warn")
						}
					}
					awsscanner.Scan(ctx, state, awsBillable, mode)

				case "azure":
					if ro := azurescanner.CheckReadOnly(ctx); ro["readonly"] == false {
						if w, ok := ro["warning"].(string); ok && w != "" {
							state.AddLog(ts(), "⚠ SECURITY: "+w, "warn")
						}
					}
					azurescanner.Scan(ctx, state, azureBillable, mode)

				case "gcp":
					if ro := gcpscanner.CheckReadOnly(ctx); ro["readonly"] == false {
						if w, ok := ro["warning"].(string); ok && w != "" {
							state.AddLog(ts(), "⚠ SECURITY: "+w, "warn")
						}
					}
					gcpscanner.Scan(ctx, state, gcpBillable, mode)

				case "oracle":
					if ro := oraclescanner.CheckReadOnly(ctx); ro["readonly"] == false {
						if w, ok := ro["warning"].(string); ok && w != "" {
							state.AddLog(ts(), "⚠ SECURITY: "+w, "warn")
						}
					}
					oraclescanner.Scan(ctx, state, oracleBillable, mode)
				}
			}()

			state.Lock()
			if scanErr != nil {
				state.CloudStatus[c].Status = "error"
				state.CloudStatus[c].Error = scanErr.Error()
				state.Errors = append(state.Errors, fmt.Sprintf("%s: %v", c, scanErr))
			} else {
				state.CloudStatus[c].Status = "done"
			}
			state.StepsDone++
			state.Progress = fmt.Sprintf("Completed %s (%d/%d)",
				strings.ToUpper(c), state.StepsDone, len(clouds))
			state.Unlock()

			if scanErr != nil {
				state.AddLog(ts(),
					fmt.Sprintf("%s failed — %v", strings.ToUpper(c), scanErr), "err")
			} else {
				state.AddLog(ts(),
					fmt.Sprintf("%s complete", strings.ToUpper(c)), "ok")
			}
		}(cloud)
	}

	wg.Wait()

	// Count resources per cloud and update CloudStatus.Count.
	state.Lock()
	for i := range state.Resources {
		c := state.Resources[i].Cloud
		if cs, ok := state.CloudStatus[c]; ok {
			cs.Count++
		}
	}
	nResources := len(state.Resources)
	nErrors    := len(state.Errors)
	state.Unlock()

	state.AddLog(ts(),
		fmt.Sprintf("All clouds done — %d total resource(s), %d error(s)",
			nResources, nErrors),
		"ok")

	// Snapshot resources for summary (outside lock for performance).
	state.RLock()
	resources := make([]scanner.Resource, len(state.Resources))
	copy(resources, state.Resources)
	state.RUnlock()

	summary := buildSummary(resources, clouds, mode)

	state.Lock()
	state.Status      = "complete"
	state.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	state.Summary     = summary
	state.Unlock()
}

// buildSummary constructs the JSON summary from all collected resources.
func buildSummary(resources []scanner.Resource, clouds []string, mode string) map[string]any {
	billableCount := 0
	byCategory   := make(map[string]map[string]int)
	byRegion     := make(map[string]map[string]int)
	byType       := make(map[string]int)
	byCloud      := make(map[string]map[string]int)

	incr := func(m map[string]map[string]int, key string, billable bool) {
		if _, ok := m[key]; !ok {
			m[key] = map[string]int{"total": 0, "billable": 0}
		}
		m[key]["total"]++
		if billable {
			m[key]["billable"]++
		}
	}

	for _, r := range resources {
		if r.Billable {
			billableCount++
		}
		incr(byCategory, r.Category, r.Billable)
		incr(byRegion, r.Region, r.Billable)
		byType[r.Type]++
		incr(byCloud, r.Cloud, r.Billable)
	}

	return map[string]any{
		"total":       len(resources),
		"billable":    billableCount,
		"by_category": byCategory,
		"by_region":   byRegion,
		"by_type":     byType,
		"by_cloud":    byCloud,
		"clouds":      clouds,
		"mode":        mode,
	}
}

// jsonResponse encodes v as JSON and writes it to w.
func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
