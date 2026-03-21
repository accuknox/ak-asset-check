package oracle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/oracle/oci-go-sdk/v65/functions"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/mysql"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	scanner "github.com/accuknox/ak-asset-check/scanner"
)

// ts returns a formatted RFC3339 timestamp for the current moment.
func ts() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// Detect checks whether OCI credentials are configured by loading the default
// config provider (~/.oci/config) and attempting to read the tenancy OCID.
func Detect() (bool, string) {
	configProvider := common.DefaultConfigProvider()
	tenancyID, err := configProvider.TenancyOCID()
	if err != nil {
		return false, ""
	}
	label := "tenancy:" + tenancyID
	if len(tenancyID) > 16 {
		label = "tenancy:" + tenancyID[:16] + "…"
	}
	return true, label
}

// CheckReadOnly inspects OCI IAM policies for the root tenancy compartment and
// reports whether any policy statements grant "manage" or "use" verbs, which
// indicate write access. A read-only setup should only use "inspect" and "read".
func CheckReadOnly(ctx context.Context) map[string]any {
	configProvider := common.DefaultConfigProvider()
	tenancyID, err := configProvider.TenancyOCID()
	if err != nil {
		return map[string]any{
			"readonly": nil,
			"enforced": false,
			"warning":  fmt.Sprintf("Could not check OCI IAM policies: %v", err),
			"method":   "none",
		}
	}

	client, err := identity.NewIdentityClientWithConfigurationProvider(configProvider)
	if err != nil {
		return map[string]any{
			"readonly": nil,
			"enforced": false,
			"warning":  fmt.Sprintf("Could not check OCI IAM policies: %v", err),
			"method":   "none",
		}
	}

	writeVerbs := []string{" manage ", " use "}
	writeStmts := 0

	req := identity.ListPoliciesRequest{CompartmentId: &tenancyID}
	for {
		resp, err := client.ListPolicies(ctx, req)
		if err != nil {
			break
		}
		for _, policy := range resp.Items {
			for _, stmt := range policy.Statements {
				lower := strings.ToLower(stmt)
				for _, v := range writeVerbs {
					if strings.Contains(lower, v) {
						writeStmts++
						break
					}
				}
			}
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}

	if writeStmts > 0 {
		return map[string]any{
			"readonly": false,
			"enforced": false,
			"method":   "iam-policy-check",
			"warning":  fmt.Sprintf("%d OCI policy statement(s) grant 'manage' or 'use' verbs. Use only 'inspect' and 'read' verbs for scanning.", writeStmts),
		}
	}
	return map[string]any{
		"readonly": true,
		"enforced": false,
		"warning":  nil,
		"method":   "iam-policy-check",
	}
}

// Scan discovers OCI resources and appends them to state. When mode is
// "billable" only billable resource types are scanned; otherwise all supported
// resource types are scanned.
func Scan(ctx context.Context, state *scanner.ScanState, billableTypes map[string]bool, mode string) {
	configProvider := common.DefaultConfigProvider()
	tenancyID, err := configProvider.TenancyOCID()
	if err != nil {
		state.AddLog(ts(), "Oracle: no credentials configured", "warn")
		return
	}

	region, _ := configProvider.Region()
	if region == "" {
		region = "us-ashburn-1"
	}

	compartments := listCompartments(ctx, configProvider, tenancyID)

	type scannerFunc func(context.Context, common.ConfigurationProvider, []string, string, map[string]bool) []scanner.Resource

	billableScanners := []struct {
		name string
		fn   scannerFunc
	}{
		{"compute instances", scanComputeInstances},
		{"object storage", scanObjectStorage},
		{"autonomous databases", scanAutonomousDatabases},
		{"mysql databases", scanMySQLDatabases},
		{"oke clusters", scanOKEClusters},
	}

	allScanners := []struct {
		name string
		fn   scannerFunc
	}{
		{"compute instances", scanComputeInstances},
		{"boot volumes", scanBootVolumes},
		{"block volumes", scanBlockVolumes},
		{"object storage", scanObjectStorage},
		{"autonomous databases", scanAutonomousDatabases},
		{"mysql databases", scanMySQLDatabases},
		{"oke clusters", scanOKEClusters},
		{"functions", scanFunctions},
		{"vcns", scanVCNs},
		{"load balancers", scanLoadBalancers},
		{"vaults", scanVaults},
	}

	scanners := billableScanners
	if mode != "billable" {
		scanners = allScanners
	}

	tenancyLabel := tenancyID
	if len(tenancyID) > 16 {
		tenancyLabel = tenancyID[:16] + "…"
	}
	state.AddLog(ts(), fmt.Sprintf("Oracle: tenancy %s, %d compartment(s), %d service(s) — mode: %s",
		tenancyLabel, len(compartments), len(scanners), mode), "info")

	for _, s := range scanners {
		found := s.fn(ctx, configProvider, compartments, region, billableTypes)
		if len(found) > 0 {
			state.AddLog(ts(), fmt.Sprintf("  %s / %s: %d resource(s)", region, s.name, len(found)), "ok")
			state.AddResources(found)
		} else {
			state.AddLog(ts(), fmt.Sprintf("  %s / %s: 0 resource(s)", region, s.name), "dim")
		}
	}
}

// listCompartments returns the tenancy root ID plus all active child compartment
// IDs reachable from the root. On any error it returns only the root ID.
func listCompartments(ctx context.Context, configProvider common.ConfigurationProvider, tenancyID string) []string {
	client, err := identity.NewIdentityClientWithConfigurationProvider(configProvider)
	if err != nil {
		return []string{tenancyID}
	}

	compartments := []string{tenancyID}
	req := identity.ListCompartmentsRequest{
		CompartmentId:          &tenancyID,
		CompartmentIdInSubtree: common.Bool(true),
		LifecycleState:         identity.CompartmentLifecycleStateActive,
	}
	for {
		resp, err := client.ListCompartments(ctx, req)
		if err != nil {
			break
		}
		for _, c := range resp.Items {
			if c.Id != nil {
				compartments = append(compartments, *c.Id)
			}
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return compartments
}

// scanComputeInstances lists all non-terminated OCI Compute instances across
// the provided compartments.
func scanComputeInstances(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := core.NewComputeClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := core.ListInstancesRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListInstances(ctx, req)
			if err != nil {
				break
			}
			for _, inst := range resp.Items {
				if inst.LifecycleState == core.InstanceLifecycleStateTerminated {
					continue
				}
				name := ""
				if inst.DisplayName != nil {
					name = *inst.DisplayName
				}
				if name == "" && inst.Id != nil {
					name = *inst.Id
				}
				shape := ""
				if inst.Shape != nil {
					shape = *inst.Shape
				}
				id := ""
				if inst.Id != nil {
					id = *inst.Id
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "Compute Instance",
					Category: "Compute",
					Region:   region,
					State:    strings.ToLower(string(inst.LifecycleState)),
					Detail:   shape,
					Cloud:    "oracle",
					Billable: billableTypes["Compute Instance"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanBootVolumes lists all non-terminated boot volumes. It first retrieves the
// availability domains for each compartment, then queries volumes per AD.
func scanBootVolumes(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	blockClient, err := core.NewBlockstorageClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}
	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID

		// Retrieve availability domains for this compartment.
		adResp, err := identityClient.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{
			CompartmentId: &compID,
		})
		if err != nil {
			continue
		}

		for _, ad := range adResp.Items {
			if ad.Name == nil {
				continue
			}
			adName := *ad.Name
			req := core.ListBootVolumesRequest{
				AvailabilityDomain: &adName,
				CompartmentId:      &compID,
			}
			for {
				resp, err := blockClient.ListBootVolumes(ctx, req)
				if err != nil {
					break
				}
				for _, vol := range resp.Items {
					if vol.LifecycleState == core.BootVolumeLifecycleStateTerminated {
						continue
					}
					name := ""
					if vol.DisplayName != nil {
						name = *vol.DisplayName
					}
					id := ""
					if vol.Id != nil {
						id = *vol.Id
					}
					if name == "" {
						name = id
					}
					detail := ""
					if vol.SizeInGBs != nil {
						detail = fmt.Sprintf("%d GiB", *vol.SizeInGBs)
					}
					resources = append(resources, scanner.Resource{
						ID:       id,
						Name:     name,
						Type:     "Boot Volume",
						Category: "Storage",
						Region:   region,
						State:    strings.ToLower(string(vol.LifecycleState)),
						Detail:   detail,
						Cloud:    "oracle",
						Billable: billableTypes["Boot Volume"],
					})
				}
				if resp.OpcNextPage == nil {
					break
				}
				req.Page = resp.OpcNextPage
			}
		}
	}
	return resources
}

// scanBlockVolumes lists all non-terminated block volumes across compartments.
func scanBlockVolumes(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := core.NewBlockstorageClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := core.ListVolumesRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListVolumes(ctx, req)
			if err != nil {
				break
			}
			for _, vol := range resp.Items {
				if vol.LifecycleState == core.VolumeLifecycleStateTerminated {
					continue
				}
				name := ""
				if vol.DisplayName != nil {
					name = *vol.DisplayName
				}
				id := ""
				if vol.Id != nil {
					id = *vol.Id
				}
				if name == "" {
					name = id
				}
				detail := ""
				if vol.SizeInGBs != nil {
					detail = fmt.Sprintf("%d GiB", *vol.SizeInGBs)
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "Block Volume",
					Category: "Storage",
					Region:   region,
					State:    strings.ToLower(string(vol.LifecycleState)),
					Detail:   detail,
					Cloud:    "oracle",
					Billable: billableTypes["Block Volume"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanObjectStorage lists all Object Storage buckets across compartments.
// The namespace is fetched once and reused for all compartment queries.
func scanObjectStorage(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	nsResp, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil {
		return nil
	}
	namespace := *nsResp.Value

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := objectstorage.ListBucketsRequest{
			NamespaceName: &namespace,
			CompartmentId: &compID,
		}
		for {
			resp, err := client.ListBuckets(ctx, req)
			if err != nil {
				break
			}
			for _, bucket := range resp.Items {
				name := ""
				if bucket.Name != nil {
					name = *bucket.Name
				}
				storageTier := ""
				resources = append(resources, scanner.Resource{
					ID:       name,
					Name:     name,
					Type:     "Object Storage Bucket",
					Category: "Storage",
					Region:   region,
					State:    "active",
					Detail:   storageTier,
					Cloud:    "oracle",
					Billable: billableTypes["Object Storage Bucket"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanAutonomousDatabases lists non-terminated, non-unavailable Autonomous
// Databases across compartments.
func scanAutonomousDatabases(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := database.NewDatabaseClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := database.ListAutonomousDatabasesRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListAutonomousDatabases(ctx, req)
			if err != nil {
				break
			}
			for _, db := range resp.Items {
				if db.LifecycleState == database.AutonomousDatabaseSummaryLifecycleStateTerminated ||
					db.LifecycleState == database.AutonomousDatabaseSummaryLifecycleStateUnavailable {
					continue
				}
				name := ""
				if db.DisplayName != nil {
					name = *db.DisplayName
				}
				id := ""
				if db.Id != nil {
					id = *db.Id
				}
				if name == "" {
					name = id
				}
				workload := ""
				if db.DbWorkload != "" {
					workload = string(db.DbWorkload)
				}
				cpus := 0
				if db.CpuCoreCount != nil {
					cpus = *db.CpuCoreCount
				}
				detail := fmt.Sprintf("%s · %d CPUs", workload, cpus)
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "Autonomous Database",
					Category: "Database",
					Region:   region,
					State:    strings.ToLower(string(db.LifecycleState)),
					Detail:   detail,
					Cloud:    "oracle",
					Billable: billableTypes["Autonomous Database"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanMySQLDatabases lists non-deleted MySQL DB Systems across compartments.
func scanMySQLDatabases(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := mysql.NewDbSystemClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := mysql.ListDbSystemsRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListDbSystems(ctx, req)
			if err != nil {
				break
			}
			for _, db := range resp.Items {
				if string(db.LifecycleState) == "DELETED" {
					continue
				}
				name := ""
				if db.DisplayName != nil {
					name = *db.DisplayName
				}
				id := ""
				if db.Id != nil {
					id = *db.Id
				}
				if name == "" {
					name = id
				}
				version := ""
				if db.MysqlVersion != nil {
					version = *db.MysqlVersion
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "MySQL Database",
					Category: "Database",
					Region:   region,
					State:    strings.ToLower(string(db.LifecycleState)),
					Detail:   version,
					Cloud:    "oracle",
					Billable: billableTypes["MySQL Database"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanOKEClusters lists non-deleted OKE (Container Engine) clusters across
// compartments.
func scanOKEClusters(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := containerengine.NewContainerEngineClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := containerengine.ListClustersRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListClusters(ctx, req)
			if err != nil {
				break
			}
			for _, cluster := range resp.Items {
				if cluster.LifecycleState == containerengine.ClusterSummaryLifecycleStateDeleted {
					continue
				}
				name := ""
				if cluster.Name != nil {
					name = *cluster.Name
				}
				id := ""
				if cluster.Id != nil {
					id = *cluster.Id
				}
				if name == "" {
					name = id
				}
				k8sVersion := ""
				if cluster.KubernetesVersion != nil {
					k8sVersion = *cluster.KubernetesVersion
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "OKE Cluster",
					Category: "Containers",
					Region:   region,
					State:    strings.ToLower(string(cluster.LifecycleState)),
					Detail:   fmt.Sprintf("k8s %s", k8sVersion),
					Cloud:    "oracle",
					Billable: billableTypes["OKE Cluster"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanFunctions lists non-deleted OCI Functions by first enumerating
// Applications per compartment, then listing Functions within each application.
func scanFunctions(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := functions.NewFunctionsManagementClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID

		// List applications in this compartment.
		appReq := functions.ListApplicationsRequest{CompartmentId: &compID}
		var appIDs []string
		for {
			appResp, err := client.ListApplications(ctx, appReq)
			if err != nil {
				break
			}
			for _, app := range appResp.Items {
				if string(app.LifecycleState) == "DELETED" {
					continue
				}
				if app.Id != nil {
					appIDs = append(appIDs, *app.Id)
				}
			}
			if appResp.OpcNextPage == nil {
				break
			}
			appReq.Page = appResp.OpcNextPage
		}

		// List functions per application.
		for _, appID := range appIDs {
			appID := appID
			fnReq := functions.ListFunctionsRequest{ApplicationId: &appID}
			for {
				fnResp, err := client.ListFunctions(ctx, fnReq)
				if err != nil {
					break
				}
				for _, fn := range fnResp.Items {
					if string(fn.LifecycleState) == "DELETED" {
						continue
					}
					name := ""
					if fn.DisplayName != nil {
						name = *fn.DisplayName
					}
					id := ""
					if fn.Id != nil {
						id = *fn.Id
					}
					if name == "" {
						name = id
					}
					memMB := int64(0)
					if fn.MemoryInMBs != nil {
						memMB = *fn.MemoryInMBs
					}
					resources = append(resources, scanner.Resource{
						ID:       id,
						Name:     name,
						Type:     "OCI Function",
						Category: "Serverless",
						Region:   region,
						State:    strings.ToLower(string(fn.LifecycleState)),
						Detail:   fmt.Sprintf("%d MB", memMB),
						Cloud:    "oracle",
						Billable: billableTypes["OCI Function"],
					})
				}
				if fnResp.OpcNextPage == nil {
					break
				}
				fnReq.Page = fnResp.OpcNextPage
			}
		}
	}
	return resources
}

// scanVCNs lists all non-terminated Virtual Cloud Networks across compartments.
func scanVCNs(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := core.ListVcnsRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListVcns(ctx, req)
			if err != nil {
				break
			}
			for _, vcn := range resp.Items {
				if vcn.LifecycleState == core.VcnLifecycleStateTerminated {
					continue
				}
				name := ""
				if vcn.DisplayName != nil {
					name = *vcn.DisplayName
				}
				id := ""
				if vcn.Id != nil {
					id = *vcn.Id
				}
				if name == "" {
					name = id
				}
				cidr := ""
				if vcn.CidrBlock != nil {
					cidr = *vcn.CidrBlock
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "Virtual Cloud Network",
					Category: "Networking",
					Region:   region,
					State:    strings.ToLower(string(vcn.LifecycleState)),
					Detail:   cidr,
					Cloud:    "oracle",
					Billable: billableTypes["Virtual Cloud Network"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanLoadBalancers lists all non-deleted Load Balancers across compartments.
func scanLoadBalancers(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := loadbalancer.NewLoadBalancerClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := loadbalancer.ListLoadBalancersRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListLoadBalancers(ctx, req)
			if err != nil {
				break
			}
			for _, lb := range resp.Items {
				if lb.LifecycleState == loadbalancer.LoadBalancerLifecycleStateDeleted {
					continue
				}
				name := ""
				if lb.DisplayName != nil {
					name = *lb.DisplayName
				}
				id := ""
				if lb.Id != nil {
					id = *lb.Id
				}
				if name == "" {
					name = id
				}
				shapeName := ""
				if lb.ShapeName != nil {
					shapeName = *lb.ShapeName
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "Load Balancer",
					Category: "Networking",
					Region:   region,
					State:    strings.ToLower(string(lb.LifecycleState)),
					Detail:   shapeName,
					Cloud:    "oracle",
					Billable: billableTypes["Load Balancer"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}

// scanVaults lists all non-deleted, non-pending-deletion KMS Vaults across
// compartments.
func scanVaults(ctx context.Context, configProvider common.ConfigurationProvider, compartments []string, region string, billableTypes map[string]bool) []scanner.Resource {
	client, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil
	}

	var resources []scanner.Resource
	for _, compID := range compartments {
		compID := compID
		req := keymanagement.ListVaultsRequest{CompartmentId: &compID}
		for {
			resp, err := client.ListVaults(ctx, req)
			if err != nil {
				break
			}
			for _, vault := range resp.Items {
				if vault.LifecycleState == keymanagement.VaultSummaryLifecycleStateDeleted ||
					vault.LifecycleState == keymanagement.VaultSummaryLifecycleStatePendingDeletion {
					continue
				}
				name := ""
				if vault.DisplayName != nil {
					name = *vault.DisplayName
				}
				id := ""
				if vault.Id != nil {
					id = *vault.Id
				}
				if name == "" {
					name = id
				}
				vaultType := ""
				if vault.VaultType != "" {
					vaultType = string(vault.VaultType)
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "OCI Vault",
					Category: "Security",
					Region:   region,
					State:    strings.ToLower(string(vault.LifecycleState)),
					Detail:   vaultType,
					Cloud:    "oracle",
					Billable: billableTypes["OCI Vault"],
				})
			}
			if resp.OpcNextPage == nil {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return resources
}
