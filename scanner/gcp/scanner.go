// Package gcp implements GCP resource scanning for ak-asset-check.
// It uses Google Cloud Go client libraries and Google API client libraries
// with Application Default Credentials (ADC).
package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	bigqueryv2 "google.golang.org/api/bigquery/v2"
	cloudfunctionsv2 "google.golang.org/api/cloudfunctions/v2"
	iamv1 "google.golang.org/api/iam/v1"
	pubsubv1 "google.golang.org/api/pubsub/v1"
	runv2 "google.golang.org/api/run/v2"
	sqladminv1 "google.golang.org/api/sqladmin/v1"
	"golang.org/x/oauth2/google"

	scanner "github.com/accuknox/ak-asset-check/scanner"
)

// gcpReadOnlyScopes are the OAuth2 scopes requested when scanning.
var gcpReadOnlyScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform.read-only",
	"https://www.googleapis.com/auth/compute.readonly",
	"https://www.googleapis.com/auth/devstorage.read_only",
}

// Detect returns (configured, label) by attempting to find Application Default
// Credentials and a project ID. The project is sourced from the credentials
// themselves or from the GOOGLE_CLOUD_PROJECT / GCLOUD_PROJECT env vars.
func Detect() (bool, string) {
	ctx := context.Background()
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return false, ""
	}
	project := creds.ProjectID
	if project == "" {
		project = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if project == "" {
		project = os.Getenv("GCLOUD_PROJECT")
	}
	if project == "" {
		return false, ""
	}
	return true, "project:" + project
}

// CheckReadOnly inspects the credential type and returns read-only metadata.
// User credentials (AuthorizedUser / OAuth2) have scopes enforced by GCP;
// service accounts do not — they rely on IAM role bindings instead.
func CheckReadOnly(ctx context.Context) map[string]any {
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return map[string]any{
			"readonly": nil,
			"enforced": false,
			"warning":  err.Error(),
			"method":   "none",
		}
	}
	credType := fmt.Sprintf("%T", creds.TokenSource)
	isUser := strings.Contains(credType, "UserCredentials") ||
		strings.Contains(credType, "AuthorizedUser")

	var warning any
	if !isUser {
		warning = "Service account detected — scope restriction is advisory only. " +
			"Ensure the service account IAM roles are read-only (roles/viewer)."
	}
	return map[string]any{
		"readonly": true,
		"enforced": isUser,
		"warning":  warning,
		"method":   "scope-restriction",
	}
}

// Scan runs all GCP sub-scanners and streams results into state.
// mode is either "billable" (subset) or "all".
func Scan(ctx context.Context, state *scanner.ScanState, billableTypes map[string]bool, mode string) {
	ok, _ := Detect()
	if !ok {
		return
	}

	// Resolve project ID (same logic as Detect).
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return
	}
	project := creds.ProjectID
	if project == "" {
		project = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if project == "" {
		project = os.Getenv("GCLOUD_PROJECT")
	}
	if project == "" {
		return
	}

	type scannerEntry struct {
		name string
		fn   func(context.Context, string) []scanner.Resource
	}

	billableScanners := []scannerEntry{
		{"compute instances", scanComputeInstances},
		{"gcs buckets", scanGCSBuckets},
		{"gke clusters", scanGKEClusters},
		{"cloud sql", scanCloudSQL},
		{"cloud functions", scanCloudFunctions},
		{"cloud run", scanCloudRun},
	}

	allScanners := []scannerEntry{
		{"compute instances", scanComputeInstances},
		{"disks", scanDisks},
		{"gcs buckets", scanGCSBuckets},
		{"gke clusters", scanGKEClusters},
		{"cloud sql", scanCloudSQL},
		{"cloud functions", scanCloudFunctions},
		{"cloud run", scanCloudRun},
		{"bigquery datasets", scanBigQueryDatasets},
		{"pubsub topics", scanPubSubTopics},
		{"vpc networks", scanVPCNetworks},
		{"load balancers", scanLoadBalancers},
		{"cloud nat", scanCloudNAT},
		{"firewall rules", scanFirewallRules},
		{"service accounts", scanServiceAccounts},
	}

	scanners := billableScanners
	if mode != "billable" {
		scanners = allScanners
	}

	ts := time.Now().Format("15:04:05")
	state.AddLog(ts, fmt.Sprintf("GCP: project %s, %d service(s) — mode: %s",
		project, len(scanners), mode), "info")

	for _, s := range scanners {
		svcName := s.name
		func() {
			defer func() {
				if r := recover(); r != nil {
					ts := time.Now().Format("15:04:05")
					state.AddLog(ts, fmt.Sprintf("  %s / %s: PANIC — %v", project, svcName, r), "err")
				}
			}()

			found := s.fn(ctx, project)

			// Stamp cloud and billable flag.
			for i := range found {
				found[i].Cloud = "gcp"
				found[i].Billable = billableTypes[found[i].Type]
			}

			ts := time.Now().Format("15:04:05")
			lvl := "dim"
			if len(found) > 0 {
				lvl = "ok"
			}
			state.AddLog(ts, fmt.Sprintf("  %s / %s: %d resource(s)", project, svcName, len(found)), lvl)
			state.AddResources(found)
		}()
	}
}

// zoneToRegion converts a zone string like "zones/us-central1-a" or
// "us-central1-a" to a region string "us-central1".
func zoneToRegion(zone string) string {
	parts := strings.Split(zone, "/")
	z := parts[len(parts)-1]
	idx := strings.LastIndex(z, "-")
	if idx < 0 {
		return z
	}
	return z[:idx]
}

// defaultOpts returns common client options with read-only scopes.
func defaultOpts() []option.ClientOption {
	return []option.ClientOption{
		option.WithScopes(gcpReadOnlyScopes...),
	}
}

// ── Per-service scanners ──────────────────────────────────────────────────────

func scanComputeInstances(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := compute.NewInstancesRESTClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	req := &computepb.AggregatedListInstancesRequest{Project: project}
	it := client.AggregatedList(ctx, req)
	for {
		pair, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		for _, inst := range pair.Value.Instances {
			status := "running"
			if inst.Status != nil {
				status = strings.ToLower(*inst.Status)
			}
			region := zoneToRegion(pair.Key)
			machineType := ""
			if inst.MachineType != nil {
				parts := strings.Split(*inst.MachineType, "/")
				machineType = parts[len(parts)-1]
			}
			id := ""
			if inst.Id != nil {
				id = fmt.Sprintf("%d", *inst.Id)
			}
			name := ""
			if inst.Name != nil {
				name = *inst.Name
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Compute Instance",
				Category: "Compute",
				Region:   region,
				State:    status,
				Detail:   machineType,
			})
		}
	}
	return resources
}

func scanDisks(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := compute.NewDisksRESTClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	req := &computepb.AggregatedListDisksRequest{Project: project}
	it := client.AggregatedList(ctx, req)
	for {
		pair, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		for _, disk := range pair.Value.Disks {
			region := zoneToRegion(pair.Key)
			state := "ready"
			if disk.Status != nil {
				state = strings.ToLower(*disk.Status)
			}
			diskType := ""
			if disk.Type != nil {
				parts := strings.Split(*disk.Type, "/")
				diskType = parts[len(parts)-1]
			}
			sizeGib := int64(0)
			if disk.SizeGb != nil {
				sizeGib = *disk.SizeGb
			}
			detail := fmt.Sprintf("%d GiB %s", sizeGib, diskType)
			id := ""
			if disk.Id != nil {
				id = fmt.Sprintf("%d", *disk.Id)
			}
			name := ""
			if disk.Name != nil {
				name = *disk.Name
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Persistent Disk",
				Category: "Storage",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanGCSBuckets(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := storage.NewClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	it := client.Buckets(ctx, project)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		region := "global"
		if attrs.Location != "" {
			region = strings.ToLower(attrs.Location)
		}
		resources = append(resources, scanner.Resource{
			ID:       attrs.Name,
			Name:     attrs.Name,
			Type:     "Cloud Storage Bucket",
			Category: "Storage",
			Region:   region,
			State:    "active",
			Detail:   attrs.StorageClass,
		})
	}
	return resources
}

func scanGKEClusters(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := container.NewClusterManagerClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	resp, err := client.ListClusters(ctx, &containerpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", project),
	})
	if err != nil {
		return resources
	}

	for _, cluster := range resp.Clusters {
		loc := cluster.Location
		if loc == "" {
			loc = "unknown"
		}
		clusterState := "unknown"
		if cluster.Status != containerpb.Cluster_STATUS_UNSPECIFIED {
			clusterState = strings.ToLower(cluster.Status.String())
		}
		id := cluster.SelfLink
		if id == "" {
			id = cluster.Name
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     cluster.Name,
			Type:     "GKE Cluster",
			Category: "Containers",
			Region:   loc,
			State:    clusterState,
			Detail:   fmt.Sprintf("k8s %s", cluster.CurrentMasterVersion),
		})
	}
	return resources
}

func scanCloudSQL(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	svc, err := sqladminv1.NewService(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}

	resp, err := svc.Instances.List(project).Context(ctx).Do()
	if err != nil {
		return resources
	}

	for _, inst := range resp.Items {
		region := inst.Region
		if region == "" {
			region = "unknown"
		}
		state := strings.ToLower(inst.State)
		if state == "" {
			state = "runnable"
		}
		resources = append(resources, scanner.Resource{
			ID:       inst.Name,
			Name:     inst.Name,
			Type:     "Cloud SQL Instance",
			Category: "Database",
			Region:   region,
			State:    state,
			Detail:   inst.DatabaseVersion,
		})
	}
	return resources
}

func scanCloudFunctions(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	svc, err := cloudfunctionsv2.NewService(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}

	parent := fmt.Sprintf("projects/%s/locations/-", project)
	resp, err := svc.Projects.Locations.Functions.List(parent).Context(ctx).Do()
	if err != nil {
		return resources
	}

	for _, fn := range resp.Functions {
		nameParts := strings.Split(fn.Name, "/")
		shortName := nameParts[len(nameParts)-1]
		region := "unknown"
		if len(nameParts) >= 4 {
			region = nameParts[3]
		}
		state := strings.ToLower(fn.State)
		if state == "" {
			state = "active"
		}
		resources = append(resources, scanner.Resource{
			ID:       fn.Name,
			Name:     shortName,
			Type:     "Cloud Function",
			Category: "Serverless",
			Region:   region,
			State:    state,
			Detail:   fn.Environment,
		})
	}
	return resources
}

func scanCloudRun(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	svc, err := runv2.NewService(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}

	parent := fmt.Sprintf("projects/%s/locations/-", project)
	resp, err := svc.Projects.Locations.Services.List(parent).Context(ctx).Do()
	if err != nil {
		return resources
	}

	for _, s := range resp.Services {
		nameParts := strings.Split(s.Name, "/")
		shortName := nameParts[len(nameParts)-1]
		region := "unknown"
		if len(nameParts) >= 4 {
			region = nameParts[3]
		}
		state := strings.ToLower(s.LaunchStage)
		if state == "" {
			state = "ga"
		}
		detail := ""
		if s.Template != nil && s.Template.Scaling != nil {
			detail = fmt.Sprintf("%d", s.Template.Scaling.MaxInstanceCount)
		}
		resources = append(resources, scanner.Resource{
			ID:       s.Name,
			Name:     shortName,
			Type:     "Cloud Run Service",
			Category: "Serverless",
			Region:   region,
			State:    state,
			Detail:   detail,
		})
	}
	return resources
}

func scanBigQueryDatasets(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	svc, err := bigqueryv2.NewService(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}

	resp, err := svc.Datasets.List(project).Context(ctx).Do()
	if err != nil {
		return resources
	}

	for _, ds := range resp.Datasets {
		dsID := ds.DatasetReference.DatasetId
		region := "unknown"
		if ds.Location != "" {
			region = strings.ToLower(ds.Location)
		}
		resources = append(resources, scanner.Resource{
			ID:       dsID,
			Name:     dsID,
			Type:     "BigQuery Dataset",
			Category: "Analytics",
			Region:   region,
			State:    "active",
			Detail:   "",
		})
	}
	return resources
}

func scanPubSubTopics(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	svc, err := pubsubv1.NewService(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}

	resp, err := svc.Projects.Topics.List(fmt.Sprintf("projects/%s", project)).Context(ctx).Do()
	if err != nil {
		return resources
	}

	for _, topic := range resp.Topics {
		nameParts := strings.Split(topic.Name, "/")
		shortName := nameParts[len(nameParts)-1]
		resources = append(resources, scanner.Resource{
			ID:       topic.Name,
			Name:     shortName,
			Type:     "Pub/Sub Topic",
			Category: "Messaging",
			Region:   "global",
			State:    "active",
			Detail:   "",
		})
	}
	return resources
}

func scanVPCNetworks(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := compute.NewNetworksRESTClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	req := &computepb.ListNetworksRequest{Project: project}
	it := client.List(ctx, req)
	for {
		network, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		routingMode := ""
		if network.RoutingConfig != nil && network.RoutingConfig.RoutingMode != nil {
			routingMode = *network.RoutingConfig.RoutingMode
		}
		id := ""
		if network.Id != nil {
			id = fmt.Sprintf("%d", *network.Id)
		}
		name := ""
		if network.Name != nil {
			name = *network.Name
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     name,
			Type:     "VPC Network",
			Category: "Networking",
			Region:   "global",
			State:    "active",
			Detail:   routingMode,
		})
	}
	return resources
}

func scanLoadBalancers(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := compute.NewUrlMapsRESTClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	req := &computepb.ListUrlMapsRequest{Project: project}
	it := client.List(ctx, req)
	for {
		urlmap, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		id := ""
		if urlmap.Id != nil {
			id = fmt.Sprintf("%d", *urlmap.Id)
		}
		name := ""
		if urlmap.Name != nil {
			name = *urlmap.Name
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     name,
			Type:     "Cloud Load Balancer",
			Category: "Networking",
			Region:   "global",
			State:    "active",
			Detail:   "",
		})
	}
	return resources
}

func scanCloudNAT(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := compute.NewRoutersRESTClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	req := &computepb.AggregatedListRoutersRequest{Project: project}
	it := client.AggregatedList(ctx, req)
	for {
		pair, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		region := strings.TrimPrefix(pair.Key, "regions/")
		for _, router := range pair.Value.Routers {
			if len(router.Nats) == 0 {
				continue
			}
			routerName := ""
			if router.Name != nil {
				routerName = *router.Name
			}
			for _, nat := range router.Nats {
				natName := ""
				if nat.Name != nil {
					natName = *nat.Name
				}
				resources = append(resources, scanner.Resource{
					ID:       fmt.Sprintf("%s/%s", routerName, natName),
					Name:     natName,
					Type:     "Cloud NAT",
					Category: "Networking",
					Region:   region,
					State:    "active",
					Detail:   routerName,
				})
			}
		}
	}
	return resources
}

func scanFirewallRules(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	client, err := compute.NewFirewallsRESTClient(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}
	defer client.Close()

	req := &computepb.ListFirewallsRequest{Project: project}
	it := client.List(ctx, req)
	for {
		fw, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		state := "active"
		if fw.Disabled != nil && *fw.Disabled {
			state = "disabled"
		}
		direction := ""
		if fw.Direction != nil {
			direction = *fw.Direction
		}
		id := ""
		if fw.Id != nil {
			id = fmt.Sprintf("%d", *fw.Id)
		}
		name := ""
		if fw.Name != nil {
			name = *fw.Name
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     name,
			Type:     "Firewall Rule",
			Category: "Security",
			Region:   "global",
			State:    state,
			Detail:   direction,
		})
	}
	return resources
}

func scanServiceAccounts(ctx context.Context, project string) []scanner.Resource {
	var resources []scanner.Resource

	svc, err := iamv1.NewService(ctx, defaultOpts()...)
	if err != nil {
		return resources
	}

	resp, err := svc.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", project)).Context(ctx).Do()
	if err != nil {
		return resources
	}

	for _, sa := range resp.Accounts {
		state := "active"
		if sa.Disabled {
			state = "disabled"
		}
		name := sa.DisplayName
		if name == "" {
			name = sa.Email
		}
		resources = append(resources, scanner.Resource{
			ID:       sa.UniqueId,
			Name:     name,
			Type:     "Service Account",
			Category: "Identity",
			Region:   "global",
			State:    state,
			Detail:   sa.Email,
		})
	}
	return resources
}
