// Package azure implements the Azure cloud asset scanner for ak-asset-check.
package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/botservice/armbotservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datalake-store/armdatalakestore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hdinsight/armhdinsight"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mariadb/armmariadb"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"

	"github.com/accuknox/ak-asset-check/scanner"
)

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func int32Val(n *int32) int32 {
	if n == nil {
		return 0
	}
	return *n
}

func nowTS() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// listResourceGroups returns all resource group names in a subscription.
func listResourceGroups(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string) []string {
	client, err := armresources.NewResourceGroupsClient(subID, cred, nil)
	if err != nil {
		return nil
	}
	var rgs []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, rg := range page.Value {
			if rg.Name != nil {
				rgs = append(rgs, *rg.Name)
			}
		}
	}
	return rgs
}

// listEnabledSubscriptions returns all enabled subscription IDs.
func listEnabledSubscriptions(ctx context.Context, cred *azidentity.DefaultAzureCredential) []*armsubscription.Subscription {
	client, err := armsubscription.NewSubscriptionsClient(cred, nil)
	if err != nil {
		return nil
	}
	var subs []*armsubscription.Subscription
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, s := range page.Value {
			if s.State != nil && strings.ToLower(string(*s.State)) == "enabled" {
				subs = append(subs, s)
			}
		}
	}
	return subs
}

// res is the resource constructor helper.
func res(rid, name, rtype, category, region, state, detail string, billableTypes map[string]bool) scanner.Resource {
	if name == "" {
		name = rid
	}
	return scanner.Resource{
		ID:       rid,
		Name:     name,
		Type:     rtype,
		Category: category,
		Region:   region,
		State:    state,
		Detail:   detail,
		Cloud:    "azure",
		Billable: billableTypes[rtype],
	}
}

// ---------------------------------------------------------------------------
// Detect
// ---------------------------------------------------------------------------

// Detect checks if Azure credentials are configured and enabled subscriptions exist.
// Returns (configured bool, label string).
func Detect() (bool, string) {
	ctx := context.Background()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return false, ""
	}
	subs := listEnabledSubscriptions(ctx, cred)
	if len(subs) == 0 {
		return false, ""
	}
	subID := strVal(subs[0].SubscriptionID)
	name := strVal(subs[0].DisplayName)
	prefix := subID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	label := name + " (" + prefix + "…)"
	return true, label
}

// ---------------------------------------------------------------------------
// CheckReadOnly
// ---------------------------------------------------------------------------

// CheckReadOnly checks if the current Azure credentials have write (Owner/Contributor) access.
func CheckReadOnly(ctx context.Context) map[string]any {
	writeRoleIDs := map[string]bool{
		"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": true, // Owner
		"b24988ac-6180-42a0-ab88-20f7382dd24c": true, // Contributor
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return map[string]any{
			"readonly": nil,
			"enforced": false,
			"warning":  "Could not create Azure credential: " + err.Error(),
			"method":   "none",
		}
	}
	subs := listEnabledSubscriptions(ctx, cred)
	if len(subs) == 0 {
		return map[string]any{
			"readonly": nil,
			"enforced": false,
			"warning":  "No enabled Azure subscriptions found",
			"method":   "none",
		}
	}
	limit := 2
	if len(subs) < limit {
		limit = len(subs)
	}
	for _, sub := range subs[:limit] {
		subID := strVal(sub.SubscriptionID)
		authClient, err := armauthorization.NewRoleAssignmentsClient(subID, cred, nil)
		if err != nil {
			continue
		}
		pager := authClient.NewListForSubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, a := range page.Value {
				if a.Properties == nil || a.Properties.RoleDefinitionID == nil {
					continue
				}
				parts := strings.Split(strVal(a.Properties.RoleDefinitionID), "/")
				roleID := strings.ToLower(parts[len(parts)-1])
				if writeRoleIDs[roleID] {
					return map[string]any{
						"readonly": false,
						"enforced": false,
						"method":   "rbac-check",
						"warning":  "Azure principal has Owner or Contributor role. Assign only the Reader built-in role.",
					}
				}
			}
		}
	}
	return map[string]any{
		"readonly": true,
		"enforced": false,
		"warning":  nil,
		"method":   "rbac-check",
	}
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

// scannerFunc is a function that scans a single service in a subscription.
type scannerFunc struct {
	name string
	fn   func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource
}

var billableScanners = []scannerFunc{
	{"virtual machines", scanVirtualMachines},
	{"vm scale sets", scanVMSS},
	{"vm scale set instances", scanVMSSInstances},
	{"container groups", scanContainerGroups},
	{"container registries", scanContainerRegistries},
	{"batch accounts", scanBatchAccounts},
	{"app service plans", scanAppServicePlans},
	{"aks", scanAKS},
	{"storage accounts", scanStorageAccounts},
	{"data lake stores", scanDataLakeStores},
	{"sql databases", scanSQLDatabases},
	{"sql managed instances", scanSQLManagedInstances},
	{"sql elastic pools", scanSQLElasticPools},
	{"cosmos db", scanCosmosDB},
	{"mysql servers", scanMySQLServers},
	{"mysql flexible servers", scanMySQLFlexibleServers},
	{"postgresql servers", scanPostgreSQLServers},
	{"postgresql flexible servers", scanPostgreSQLFlexibleServers},
	{"mariadb servers", scanMariaDBServers},
	{"redis caches", scanRedisCaches},
	{"application gateways", scanApplicationGateways},
	{"firewalls", scanFirewalls},
	{"nat gateways", scanNATGateways},
	{"vnet gateways", scanVNetGateways},
	{"express route circuits", scanExpressRouteCircuits},
	{"bastion hosts", scanBastionHosts},
	{"eventhub namespaces", scanEventHubNamespaces},
	{"servicebus namespaces", scanServiceBusNamespaces},
	{"iothub", scanIoTHub},
	{"synapse workspaces", scanSynapseWorkspaces},
	{"databricks workspaces", scanDatabricksWorkspaces},
	{"data factories", scanDataFactories},
	{"hdinsight clusters", scanHDInsightClusters},
	{"kusto clusters", scanKustoClusters},
	{"stream analytics jobs", scanStreamAnalyticsJobs},
	{"search services", scanSearchServices},
	{"cognitive services", scanCognitiveServices},
	{"ml workspaces", scanMLWorkspaces},
	{"bot services", scanBotServices},
	{"functions", scanFunctions},
	{"api management", scanAPIManagement},
	{"signalr services", scanSignalRServices},
	{"spring cloud services", scanSpringCloudServices},
	{"recovery vaults", scanRecoveryVaults},
}

var extraScanners = []scannerFunc{
	{"availability sets", scanAvailabilitySets},
	{"compute images", scanComputeImages},
	{"disks", scanDisks},
	{"snapshots", scanSnapshots},
	{"app services", scanAppServices},
	{"app configurations", scanAppConfigurations},
	{"automation accounts", scanAutomationAccounts},
	{"app insights", scanAppInsights},
	{"log analytics workspaces", scanLogAnalyticsWorkspaces},
	{"key vaults", scanKeyVaults},
	{"waf policies", scanWAFPolicies},
	{"vnets", scanVNets},
	{"load balancers", scanLoadBalancers},
	{"public ips", scanPublicIPs},
	{"network security groups", scanNetworkSecurityGroups},
	{"dns zones", scanDNSZones},
	{"private dns zones", scanPrivateDNSZones},
	{"route tables", scanRouteTables},
	{"private endpoints", scanPrivateEndpoints},
	{"eventgrid domains", scanEventGridDomains},
	{"eventgrid topics", scanEventGridTopics},
	{"logic apps", scanLogicApps},
	{"arc machines", scanArcMachines},
}

// Scan runs the Azure asset scan and appends results to state.
func Scan(ctx context.Context, state *scanner.ScanState, billableTypes map[string]bool, mode string) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		state.AddLog(nowTS(), "Azure: credential error — "+err.Error(), "err")
		return
	}
	subs := listEnabledSubscriptions(ctx, cred)
	if len(subs) == 0 {
		state.AddLog(nowTS(), "Azure: no enabled subscriptions found", "warn")
		return
	}

	scanners := billableScanners
	if mode != "billable" {
		scanners = append(billableScanners, extraScanners...)
	}

	state.AddLog(nowTS(),
		fmt.Sprintf("Azure: %d subscription(s), %d service(s) — mode: %s", len(subs), len(scanners), mode),
		"info")

	for _, sub := range subs {
		subID := strVal(sub.SubscriptionID)
		prefix := subID
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		state.AddLog(nowTS(), fmt.Sprintf("Azure: scanning subscription %s…", prefix), "info")

		for _, sc := range scanners {
			var found []scanner.Resource
			func() {
				defer func() {
					if r := recover(); r != nil {
						state.AddLog(nowTS(),
							fmt.Sprintf("  %s / %s: PANIC — %v", prefix, sc.name, r),
							"err")
					}
				}()
				found = sc.fn(ctx, cred, subID, billableTypes)
			}()

			if found == nil {
				// scanner panicked or had an error — already logged
				continue
			}

			lvl := "dim"
			if len(found) > 0 {
				lvl = "ok"
			}
			state.AddLog(nowTS(),
				fmt.Sprintf("  %s / %s: %d resource(s)", prefix, sc.name, len(found)),
				lvl)
			if len(found) > 0 {
				state.AddResources(found)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Compute scanners
// ---------------------------------------------------------------------------

func scanVirtualMachines(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcompute.NewVirtualMachinesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vm := range page.Value {
			id := strVal(vm.ID)
			name := strVal(vm.Name)
			region := strVal(vm.Location)
			state := "unknown"
			detail := ""
			if vm.Properties != nil {
				if vm.Properties.HardwareProfile != nil && vm.Properties.HardwareProfile.VMSize != nil {
					detail = string(*vm.Properties.HardwareProfile.VMSize)
				}
				if vm.Properties.InstanceView != nil {
					for _, s := range vm.Properties.InstanceView.Statuses {
						code := strVal(s.Code)
						if strings.HasPrefix(code, "PowerState/") {
							state = strings.TrimPrefix(code, "PowerState/")
							break
						}
					}
				}
			}
			result = append(result, res(id, name, "Virtual Machine", "Compute", region, state, detail, billableTypes))
		}
	}
	return result
}

func scanDisks(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcompute.NewDisksClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, disk := range page.Value {
			id := strVal(disk.ID)
			name := strVal(disk.Name)
			region := strVal(disk.Location)
			state := ""
			detail := ""
			if disk.Properties != nil {
				if disk.Properties.DiskState != nil {
					state = strings.ToLower(string(*disk.Properties.DiskState))
				}
				sizeGB := int32Val(disk.Properties.DiskSizeGB)
				skuName := ""
				if disk.SKU != nil && disk.SKU.Name != nil {
					skuName = string(*disk.SKU.Name)
				}
				detail = fmt.Sprintf("%d GiB %s", sizeGB, skuName)
			}
			result = append(result, res(id, name, "Managed Disk", "Storage", region, state, detail, billableTypes))
		}
	}
	return result
}

func scanSnapshots(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcompute.NewSnapshotsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, snap := range page.Value {
			id := strVal(snap.ID)
			name := strVal(snap.Name)
			region := strVal(snap.Location)
			state := ""
			detail := ""
			if snap.Properties != nil {
				state = strings.ToLower(strVal(snap.Properties.ProvisioningState))
				sizeGB := int32Val(snap.Properties.DiskSizeGB)
				detail = fmt.Sprintf("%d GiB", sizeGB)
			}
			result = append(result, res(id, name, "Disk Snapshot", "Storage", region, state, detail, billableTypes))
		}
	}
	return result
}

func scanVMSS(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcompute.NewVirtualMachineScaleSetsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vmss := range page.Value {
			id := strVal(vmss.ID)
			name := strVal(vmss.Name)
			region := strVal(vmss.Location)
			state := "running"
			detail := ""
			if vmss.SKU != nil && vmss.SKU.Name != nil {
				detail = strVal(vmss.SKU.Name)
			}
			// Annotate AKS-managed scale sets
			if vmss.Tags != nil {
				poolName := strVal(vmss.Tags["aks-managed-poolName"])
				clusterName := strVal(vmss.Tags["aks-managed-cluster-name"])
				if poolName != "" || clusterName != "" {
					detail = strings.TrimSpace(detail + " [AKS: " + clusterName + "/" + poolName + "]")
				}
			}
			result = append(result, res(id, name, "VM Scale Set", "Compute", region, state, detail, billableTypes))
		}
	}
	return result
}

func scanVMSSInstances(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	ssClient, err := armcompute.NewVirtualMachineScaleSetsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	vmClient, err := armcompute.NewVirtualMachineScaleSetVMsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	ssPager := ssClient.NewListAllPager(nil)
	for ssPager.More() {
		ssPage, err := ssPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vmss := range ssPage.Value {
			ssName := strVal(vmss.Name)
			// Extract resource group from ID
			rgName := resourceGroupFromID(strVal(vmss.ID))
			if rgName == "" || ssName == "" {
				continue
			}
			vmSize := ""
			if vmss.SKU != nil && vmss.SKU.Name != nil {
				vmSize = strVal(vmss.SKU.Name)
			}
			aksInfo := ""
			if vmss.Tags != nil {
				poolName := strVal(vmss.Tags["aks-managed-poolName"])
				clusterName := strVal(vmss.Tags["aks-managed-cluster-name"])
				if poolName != "" || clusterName != "" {
					aksInfo = " [AKS: " + clusterName + "/" + poolName + "]"
				}
			}

			vmPager := vmClient.NewListPager(rgName, ssName, nil)
			for vmPager.More() {
				vmPage, err := vmPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, vm := range vmPage.Value {
					id := strVal(vm.ID)
					name := strVal(vm.Name)
					region := strVal(vm.Location)
					state := "unknown"
					if vm.Properties != nil && vm.Properties.InstanceView != nil {
						for _, s := range vm.Properties.InstanceView.Statuses {
							code := strVal(s.Code)
							if strings.HasPrefix(code, "PowerState/") {
								state = strings.TrimPrefix(code, "PowerState/")
								break
							}
						}
					}
					detail := vmSize + aksInfo
					result = append(result, res(id, name, "VM Scale Set Instance", "Compute", region, state, detail, billableTypes))
				}
			}
		}
	}
	return result
}

func scanAvailabilitySets(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcompute.NewAvailabilitySetsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, as := range page.Value {
			result = append(result, res(strVal(as.ID), strVal(as.Name), "Availability Set", "Compute", strVal(as.Location), "active", "", billableTypes))
		}
	}
	return result
}

func scanComputeImages(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcompute.NewImagesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, img := range page.Value {
			detail := ""
			if img.Properties != nil && img.Properties.HyperVGeneration != nil {
				detail = string(*img.Properties.HyperVGeneration)
			}
			result = append(result, res(strVal(img.ID), strVal(img.Name), "Compute Image", "Compute", strVal(img.Location), "active", detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Container scanners
// ---------------------------------------------------------------------------

func scanAKS(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcontainerservice.NewManagedClustersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.Value {
			id := strVal(cluster.ID)
			name := strVal(cluster.Name)
			region := strVal(cluster.Location)
			state := ""
			detail := ""
			if cluster.Properties != nil {
				state = strings.ToLower(strVal(cluster.Properties.ProvisioningState))
				detail = "k8s " + strVal(cluster.Properties.KubernetesVersion)
			}
			result = append(result, res(id, name, "AKS Cluster", "Containers", region, state, detail, billableTypes))
		}
	}
	return result
}

func scanContainerGroups(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcontainerinstance.NewContainerGroupsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cg := range page.Value {
			id := strVal(cg.ID)
			name := strVal(cg.Name)
			region := strVal(cg.Location)
			state := ""
			detail := ""
			if cg.Properties != nil {
				if cg.Properties.ProvisioningState != nil {
					state = strings.ToLower(strVal(cg.Properties.ProvisioningState))
				}
				osType := ""
				if cg.Properties.OSType != nil {
					osType = string(*cg.Properties.OSType)
				}
				detail = fmt.Sprintf("%d container(s) · %s", len(cg.Properties.Containers), osType)
			}
			result = append(result, res(id, name, "Container Group", "Containers", region, state, detail, billableTypes))
		}
	}
	return result
}

func scanContainerRegistries(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, reg := range page.Value {
			detail := ""
			if reg.SKU != nil && reg.SKU.Name != nil {
				detail = string(*reg.SKU.Name)
			}
			state := ""
			if reg.Properties != nil && reg.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*reg.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(reg.ID), strVal(reg.Name), "Container Registry", "Containers", strVal(reg.Location), state, detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Storage scanners
// ---------------------------------------------------------------------------

func scanStorageAccounts(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armstorage.NewAccountsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			state := ""
			detail := ""
			if acct.Properties != nil && acct.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*acct.Properties.ProvisioningState))
			}
			if acct.Kind != nil {
				detail = string(*acct.Kind)
			}
			result = append(result, res(strVal(acct.ID), strVal(acct.Name), "Storage Account", "Storage", strVal(acct.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanDataLakeStores(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armdatalakestore.NewAccountsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			state := ""
			if acct.Properties != nil && acct.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*acct.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(acct.ID), strVal(acct.Name), "Data Lake Store", "Storage", strVal(acct.Location), state, "", billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Database scanners
// ---------------------------------------------------------------------------

func scanSQLDatabases(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	serverClient, err := armsql.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	dbClient, err := armsql.NewDatabasesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	sPager := serverClient.NewListPager(nil)
	for sPager.More() {
		sPage, err := sPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range sPage.Value {
			rgName := resourceGroupFromID(strVal(srv.ID))
			srvName := strVal(srv.Name)
			dPager := dbClient.NewListByServerPager(rgName, srvName, nil)
			for dPager.More() {
				dPage, err := dPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, db := range dPage.Value {
					if strVal(db.Name) == "master" {
						continue
					}
					state := ""
					detail := ""
					if db.Properties != nil && db.Properties.Status != nil {
						state = strings.ToLower(string(*db.Properties.Status))
					}
					if db.SKU != nil && db.SKU.Name != nil {
						detail = strVal(db.SKU.Name)
					}
					result = append(result, res(strVal(db.ID), strVal(db.Name), "SQL Database", "Database", strVal(db.Location), state, detail, billableTypes))
				}
			}
		}
	}
	return result
}

func scanSQLManagedInstances(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armsql.NewManagedInstancesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, mi := range page.Value {
			state := ""
			if mi.Properties != nil && mi.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*mi.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(mi.ID), strVal(mi.Name), "SQL Managed Instance", "Database", strVal(mi.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanSQLElasticPools(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	serverClient, err := armsql.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	epClient, err := armsql.NewElasticPoolsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	sPager := serverClient.NewListPager(nil)
	for sPager.More() {
		sPage, err := sPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range sPage.Value {
			rgName := resourceGroupFromID(strVal(srv.ID))
			srvName := strVal(srv.Name)
			epPager := epClient.NewListByServerPager(rgName, srvName, nil)
			for epPager.More() {
				epPage, err := epPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, pool := range epPage.Value {
					state := ""
					if pool.Properties != nil && pool.Properties.State != nil {
						state = strings.ToLower(string(*pool.Properties.State))
					}
					result = append(result, res(strVal(pool.ID), strVal(pool.Name), "SQL Elastic Pool", "Database", strVal(pool.Location), state, "", billableTypes))
				}
			}
		}
	}
	return result
}

func scanCosmosDB(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			state := ""
			detail := ""
			if acct.Properties != nil {
				state = strings.ToLower(strVal(acct.Properties.ProvisioningState))
			}
			if acct.Kind != nil {
				detail = string(*acct.Kind)
			}
			result = append(result, res(strVal(acct.ID), strVal(acct.Name), "Cosmos DB", "Database", strVal(acct.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanMySQLServers(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armmysql.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range page.Value {
			state := ""
			if srv.Properties != nil && srv.Properties.UserVisibleState != nil {
				state = strings.ToLower(string(*srv.Properties.UserVisibleState))
			}
			result = append(result, res(strVal(srv.ID), strVal(srv.Name), "MySQL Server", "Database", strVal(srv.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanMySQLFlexibleServers(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armmysqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range page.Value {
			state := ""
			if srv.Properties != nil && srv.Properties.State != nil {
				state = strings.ToLower(string(*srv.Properties.State))
			}
			result = append(result, res(strVal(srv.ID), strVal(srv.Name), "MySQL Flexible Server", "Database", strVal(srv.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanPostgreSQLServers(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armpostgresql.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range page.Value {
			state := ""
			if srv.Properties != nil && srv.Properties.UserVisibleState != nil {
				state = strings.ToLower(string(*srv.Properties.UserVisibleState))
			}
			result = append(result, res(strVal(srv.ID), strVal(srv.Name), "PostgreSQL Server", "Database", strVal(srv.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanPostgreSQLFlexibleServers(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armpostgresqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range page.Value {
			state := ""
			if srv.Properties != nil && srv.Properties.State != nil {
				state = strings.ToLower(string(*srv.Properties.State))
			}
			result = append(result, res(strVal(srv.ID), strVal(srv.Name), "PostgreSQL Flexible Server", "Database", strVal(srv.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanMariaDBServers(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armmariadb.NewServersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, srv := range page.Value {
			state := ""
			if srv.Properties != nil && srv.Properties.UserVisibleState != nil {
				state = strings.ToLower(string(*srv.Properties.UserVisibleState))
			}
			result = append(result, res(strVal(srv.ID), strVal(srv.Name), "MariaDB Server", "Database", strVal(srv.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanRedisCaches(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armredis.NewClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cache := range page.Value {
			state := ""
			detail := ""
			if cache.Properties != nil {
				if cache.Properties.ProvisioningState != nil {
					state = strings.ToLower(string(*cache.Properties.ProvisioningState))
				}
				if cache.Properties.SKU != nil {
					skuName := string(*cache.Properties.SKU.Name)
					detail = fmt.Sprintf("%s C%d", skuName, cache.Properties.SKU.Capacity)
				}
			}
			result = append(result, res(strVal(cache.ID), strVal(cache.Name), "Redis Cache", "Database", strVal(cache.Location), state, detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Networking scanners
// ---------------------------------------------------------------------------

func scanVNets(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewVirtualNetworksClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vnet := range page.Value {
			state := ""
			detail := ""
			if vnet.Properties != nil {
				if vnet.Properties.ProvisioningState != nil {
					state = strings.ToLower(string(*vnet.Properties.ProvisioningState))
				}
				var prefixes []string
				if vnet.Properties.AddressSpace != nil {
					for _, p := range vnet.Properties.AddressSpace.AddressPrefixes {
						prefixes = append(prefixes, strVal(p))
					}
				}
				detail = strings.Join(prefixes, ", ")
			}
			result = append(result, res(strVal(vnet.ID), strVal(vnet.Name), "Virtual Network", "Networking", strVal(vnet.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanLoadBalancers(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewLoadBalancersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, lb := range page.Value {
			state := ""
			detail := ""
			if lb.Properties != nil && lb.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*lb.Properties.ProvisioningState))
			}
			if lb.SKU != nil && lb.SKU.Name != nil {
				detail = string(*lb.SKU.Name)
			}
			result = append(result, res(strVal(lb.ID), strVal(lb.Name), "Load Balancer", "Networking", strVal(lb.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanPublicIPs(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewPublicIPAddressesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ip := range page.Value {
			state := ""
			detail := "unassigned"
			if ip.Properties != nil {
				if ip.Properties.ProvisioningState != nil {
					state = strings.ToLower(string(*ip.Properties.ProvisioningState))
				}
				if ip.Properties.IPAddress != nil && *ip.Properties.IPAddress != "" {
					detail = *ip.Properties.IPAddress
				}
			}
			result = append(result, res(strVal(ip.ID), strVal(ip.Name), "Public IP", "Networking", strVal(ip.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanNetworkSecurityGroups(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewSecurityGroupsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, nsg := range page.Value {
			state := ""
			if nsg.Properties != nil && nsg.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*nsg.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(nsg.ID), strVal(nsg.Name), "Network Security Group", "Security", strVal(nsg.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanApplicationGateways(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewApplicationGatewaysClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, agw := range page.Value {
			state := ""
			detail := ""
			if agw.Properties != nil && agw.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*agw.Properties.ProvisioningState))
			}
			if agw.Properties != nil && agw.Properties.SKU != nil && agw.Properties.SKU.Name != nil {
				detail = string(*agw.Properties.SKU.Name)
			}
			result = append(result, res(strVal(agw.ID), strVal(agw.Name), "Application Gateway", "Networking", strVal(agw.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanFirewalls(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewAzureFirewallsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fw := range page.Value {
			state := ""
			detail := ""
			if fw.Properties != nil && fw.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*fw.Properties.ProvisioningState))
			}
			if fw.Properties != nil && fw.Properties.SKU != nil && fw.Properties.SKU.Name != nil {
				detail = string(*fw.Properties.SKU.Name)
			}
			result = append(result, res(strVal(fw.ID), strVal(fw.Name), "Azure Firewall", "Security", strVal(fw.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanNATGateways(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewNatGatewaysClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ng := range page.Value {
			state := ""
			if ng.Properties != nil && ng.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*ng.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(ng.ID), strVal(ng.Name), "NAT Gateway", "Networking", strVal(ng.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanVNetGateways(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	gwClient, err := armnetwork.NewVirtualNetworkGatewaysClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	rgs := listResourceGroups(ctx, cred, subID)
	var result []scanner.Resource
	for _, rg := range rgs {
		pager := gwClient.NewListPager(rg, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, gw := range page.Value {
				state := ""
				detail := ""
				if gw.Properties != nil && gw.Properties.ProvisioningState != nil {
					state = strings.ToLower(string(*gw.Properties.ProvisioningState))
				}
				if gw.Properties != nil && gw.Properties.SKU != nil && gw.Properties.SKU.Name != nil {
					detail = string(*gw.Properties.SKU.Name)
				}
				result = append(result, res(strVal(gw.ID), strVal(gw.Name), "VNet Gateway", "Networking", strVal(gw.Location), state, detail, billableTypes))
			}
		}
	}
	return result
}

func scanExpressRouteCircuits(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewExpressRouteCircuitsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, circuit := range page.Value {
			state := ""
			detail := ""
			if circuit.Properties != nil && circuit.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*circuit.Properties.ProvisioningState))
			}
			if circuit.SKU != nil && circuit.SKU.Name != nil {
				detail = strVal(circuit.SKU.Name)
			}
			result = append(result, res(strVal(circuit.ID), strVal(circuit.Name), "ExpressRoute Circuit", "Networking", strVal(circuit.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanBastionHosts(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewBastionHostsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, bh := range page.Value {
			state := ""
			detail := ""
			if bh.Properties != nil && bh.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*bh.Properties.ProvisioningState))
			}
			if bh.SKU != nil && bh.SKU.Name != nil {
				detail = string(*bh.SKU.Name)
			}
			result = append(result, res(strVal(bh.ID), strVal(bh.Name), "Bastion Host", "Networking", strVal(bh.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanDNSZones(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armdns.NewZonesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, zone := range page.Value {
			region := strVal(zone.Location)
			if region == "" {
				region = "global"
			}
			detail := ""
			if zone.Properties != nil && zone.Properties.NumberOfRecordSets != nil {
				detail = fmt.Sprintf("%d record set(s)", *zone.Properties.NumberOfRecordSets)
			}
			result = append(result, res(strVal(zone.ID), strVal(zone.Name), "DNS Zone", "Networking", region, "active", detail, billableTypes))
		}
	}
	return result
}

func scanPrivateDNSZones(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armprivatedns.NewPrivateZonesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, zone := range page.Value {
			state := ""
			if zone.Properties != nil && zone.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*zone.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(zone.ID), strVal(zone.Name), "Private DNS Zone", "Networking", strVal(zone.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanRouteTables(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewRouteTablesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, rt := range page.Value {
			state := ""
			if rt.Properties != nil && rt.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*rt.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(rt.ID), strVal(rt.Name), "Route Table", "Networking", strVal(rt.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanPrivateEndpoints(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewPrivateEndpointsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pe := range page.Value {
			state := ""
			if pe.Properties != nil && pe.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*pe.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(pe.ID), strVal(pe.Name), "Private Endpoint", "Networking", strVal(pe.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanWAFPolicies(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armnetwork.NewWebApplicationFirewallPoliciesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pol := range page.Value {
			state := ""
			if pol.Properties != nil && pol.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*pol.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(pol.ID), strVal(pol.Name), "WAF Policy", "Security", strVal(pol.Location), state, "", billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Messaging scanners
// ---------------------------------------------------------------------------

func scanEventHubNamespaces(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armeventhub.NewNamespacesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ns := range page.Value {
			state := ""
			if ns.Properties != nil && ns.Properties.ProvisioningState != nil {
				state = strings.ToLower(strVal(ns.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(ns.ID), strVal(ns.Name), "Event Hub Namespace", "Messaging", strVal(ns.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanServiceBusNamespaces(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armservicebus.NewNamespacesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ns := range page.Value {
			state := ""
			if ns.Properties != nil && ns.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*ns.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(ns.ID), strVal(ns.Name), "Service Bus Namespace", "Messaging", strVal(ns.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanEventGridDomains(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armeventgrid.NewDomainsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, d := range page.Value {
			state := ""
			if d.Properties != nil && d.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*d.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(d.ID), strVal(d.Name), "Event Grid Domain", "Messaging", strVal(d.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanEventGridTopics(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armeventgrid.NewTopicsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, t := range page.Value {
			state := ""
			if t.Properties != nil && t.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*t.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(t.ID), strVal(t.Name), "Event Grid Topic", "Messaging", strVal(t.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanIoTHub(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armiothub.NewResourceClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, hub := range page.Value {
			state := ""
			if hub.Properties != nil && hub.Properties.State != nil {
				state = strings.ToLower(strVal(hub.Properties.State))
			}
			result = append(result, res(strVal(hub.ID), strVal(hub.Name), "IoT Hub", "Messaging", strVal(hub.Location), state, "", billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Integration scanners
// ---------------------------------------------------------------------------

func scanLogicApps(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armlogic.NewWorkflowsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, wf := range page.Value {
			state := ""
			if wf.Properties != nil && wf.Properties.State != nil {
				state = strings.ToLower(string(*wf.Properties.State))
			}
			result = append(result, res(strVal(wf.ID), strVal(wf.Name), "Logic App", "Integration", strVal(wf.Location), state, "", billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Analytics scanners
// ---------------------------------------------------------------------------

func scanSynapseWorkspaces(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armsynapse.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ws := range page.Value {
			state := ""
			if ws.Properties != nil && ws.Properties.ProvisioningState != nil {
				state = strings.ToLower(strVal(ws.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(ws.ID), strVal(ws.Name), "Synapse Workspace", "Analytics", strVal(ws.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanDatabricksWorkspaces(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armdatabricks.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ws := range page.Value {
			state := ""
			detail := ""
			if ws.Properties != nil && ws.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*ws.Properties.ProvisioningState))
			}
			if ws.SKU != nil && ws.SKU.Name != nil {
				detail = strVal(ws.SKU.Name)
			}
			result = append(result, res(strVal(ws.ID), strVal(ws.Name), "Databricks Workspace", "Analytics", strVal(ws.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanDataFactories(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armdatafactory.NewFactoriesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, df := range page.Value {
			state := ""
			if df.Properties != nil && df.Properties.ProvisioningState != nil {
				state = strings.ToLower(strVal(df.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(df.ID), strVal(df.Name), "Data Factory", "Analytics", strVal(df.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanHDInsightClusters(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armhdinsight.NewClustersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.Value {
			state := ""
			detail := ""
			if cluster.Properties != nil {
				if cluster.Properties.ClusterState != nil {
					state = strings.ToLower(strVal(cluster.Properties.ClusterState))
				}
				if cluster.Properties.ClusterDefinition != nil && cluster.Properties.ClusterDefinition.Kind != nil {
					detail = strVal(cluster.Properties.ClusterDefinition.Kind)
				}
			}
			result = append(result, res(strVal(cluster.ID), strVal(cluster.Name), "HDInsight Cluster", "Analytics", strVal(cluster.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanKustoClusters(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armkusto.NewClustersClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.Value {
			state := ""
			detail := ""
			if cluster.Properties != nil && cluster.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*cluster.Properties.ProvisioningState))
			}
			if cluster.SKU != nil && cluster.SKU.Name != nil {
				detail = string(*cluster.SKU.Name)
			}
			result = append(result, res(strVal(cluster.ID), strVal(cluster.Name), "Data Explorer Cluster", "Analytics", strVal(cluster.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanStreamAnalyticsJobs(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armstreamanalytics.NewStreamingJobsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, job := range page.Value {
			state := ""
			detail := ""
			if job.Properties != nil {
				if job.Properties.JobState != nil {
					state = strings.ToLower(strVal(job.Properties.JobState))
				}
				if job.Properties.SKU != nil && job.Properties.SKU.Name != nil {
					detail = string(*job.Properties.SKU.Name)
				}
			}
			result = append(result, res(strVal(job.ID), strVal(job.Name), "Stream Analytics Job", "Analytics", strVal(job.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanSearchServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armsearch.NewServicesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, svc := range page.Value {
			state := ""
			if svc.Properties != nil && svc.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*svc.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(svc.ID), strVal(svc.Name), "Search Service", "Analytics", strVal(svc.Location), state, "", billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// AI / ML scanners
// ---------------------------------------------------------------------------

func scanCognitiveServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armcognitiveservices.NewAccountsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	kindToType := map[string]string{
		"OpenAI":          "Azure OpenAI",
		"AIServices":      "Azure AI Services",
		"TextAnalytics":   "Azure AI Language",
		"ComputerVision":  "Azure AI Vision",
		"SpeechServices":  "Azure AI Speech",
		"FormRecognizer":  "Azure AI Document Intelligence",
		"ContentSafety":   "Azure AI Content Safety",
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			kind := strVal(acct.Kind)
			rtype, ok := kindToType[kind]
			if !ok {
				rtype = "Cognitive Services"
			}
			state := ""
			if acct.Properties != nil && acct.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*acct.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(acct.ID), strVal(acct.Name), rtype, "AI / ML", strVal(acct.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanMLWorkspaces(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armmachinelearning.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ws := range page.Value {
			kind := strVal(ws.Kind)
			rtype := "ML Workspace"
			switch kind {
			case "Hub":
				rtype = "AI Foundry Hub"
			case "Project":
				rtype = "AI Foundry Project"
			case "FeatureStore":
				rtype = "Feature Store"
			}
			state := ""
			if ws.Properties != nil && ws.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*ws.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(ws.ID), strVal(ws.Name), rtype, "AI / ML", strVal(ws.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanBotServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armbotservice.NewBotsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, bot := range page.Value {
			state := ""
			detail := ""
			if bot.Kind != nil {
				detail = string(*bot.Kind)
			}
			if bot.Properties != nil && bot.Properties.ProvisioningState != nil {
				state = strings.ToLower(strVal(bot.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(bot.ID), strVal(bot.Name), "Bot Service", "AI / ML", strVal(bot.Location), state, detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// App / Serverless scanners
// ---------------------------------------------------------------------------

func scanAppServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, app := range page.Value {
			kind := strVal(app.Kind)
			if strings.Contains(strings.ToLower(kind), "functionapp") {
				continue // handled by scanFunctions
			}
			state := ""
			if app.Properties != nil && app.Properties.State != nil {
				state = strings.ToLower(strVal(app.Properties.State))
			}
			result = append(result, res(strVal(app.ID), strVal(app.Name), "App Service", "Compute", strVal(app.Location), state, kind, billableTypes))
		}
	}
	return result
}

func scanFunctions(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, app := range page.Value {
			kind := strVal(app.Kind)
			if !strings.Contains(strings.ToLower(kind), "functionapp") {
				continue
			}
			state := ""
			if app.Properties != nil && app.Properties.State != nil {
				state = strings.ToLower(strVal(app.Properties.State))
			}
			result = append(result, res(strVal(app.ID), strVal(app.Name), "Azure Function", "Serverless", strVal(app.Location), state, kind, billableTypes))
		}
	}
	return result
}

func scanAppServicePlans(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armappservice.NewPlansClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, plan := range page.Value {
			state := ""
			detail := ""
			if plan.Properties != nil && plan.Properties.Status != nil {
				state = strings.ToLower(string(*plan.Properties.Status))
			}
			if plan.SKU != nil && plan.SKU.Name != nil {
				detail = strVal(plan.SKU.Name)
			}
			result = append(result, res(strVal(plan.ID), strVal(plan.Name), "App Service Plan", "Compute", strVal(plan.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanAPIManagement(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armapimanagement.NewServiceClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, svc := range page.Value {
			detail := ""
			if svc.SKU != nil && svc.SKU.Name != nil {
				detail = string(*svc.SKU.Name)
			}
			state := ""
			if svc.Properties != nil && svc.Properties.ProvisioningState != nil {
				state = strings.ToLower(strVal(svc.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(svc.ID), strVal(svc.Name), "API Management", "API", strVal(svc.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanSignalRServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armsignalr.NewClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, svc := range page.Value {
			detail := ""
			if svc.SKU != nil && svc.SKU.Name != nil {
				detail = strVal(svc.SKU.Name)
			}
			state := ""
			if svc.Properties != nil && svc.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*svc.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(svc.ID), strVal(svc.Name), "SignalR Service", "Application", strVal(svc.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanSpringCloudServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armappplatform.NewServicesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, svc := range page.Value {
			state := ""
			detail := ""
			if svc.Properties != nil && svc.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*svc.Properties.ProvisioningState))
			}
			if svc.SKU != nil && svc.SKU.Name != nil {
				detail = strVal(svc.SKU.Name)
			}
			result = append(result, res(strVal(svc.ID), strVal(svc.Name), "Spring Cloud Service", "Application", strVal(svc.Location), state, detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Security / Management scanners
// ---------------------------------------------------------------------------

func scanKeyVaults(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armkeyvault.NewVaultsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, kv := range page.Value {
			result = append(result, res(strVal(kv.ID), strVal(kv.Name), "Key Vault", "Security", strVal(kv.Location), "active", "", billableTypes))
		}
	}
	return result
}

func scanAppConfigurations(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armappconfiguration.NewConfigurationStoresClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, store := range page.Value {
			detail := ""
			if store.SKU != nil && store.SKU.Name != nil {
				detail = strVal(store.SKU.Name)
			}
			state := ""
			if store.Properties != nil && store.Properties.ProvisioningState != nil {
				state = strings.ToLower(string(*store.Properties.ProvisioningState))
			}
			result = append(result, res(strVal(store.ID), strVal(store.Name), "App Configuration", "Application", strVal(store.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanAutomationAccounts(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armautomation.NewAccountClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			state := ""
			if acct.Properties != nil && acct.Properties.State != nil {
				state = strings.ToLower(string(*acct.Properties.State))
			}
			result = append(result, res(strVal(acct.ID), strVal(acct.Name), "Automation Account", "Management", strVal(acct.Location), state, "", billableTypes))
		}
	}
	return result
}

func scanBatchAccounts(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armbatch.NewAccountClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acct := range page.Value {
			state := ""
			detail := ""
			if acct.Properties != nil {
				if acct.Properties.ProvisioningState != nil {
					state = strings.ToLower(string(*acct.Properties.ProvisioningState))
				}
				if acct.Properties.DedicatedCoreQuota != nil {
					detail = fmt.Sprintf("%d dedicated cores", *acct.Properties.DedicatedCoreQuota)
				}
			}
			result = append(result, res(strVal(acct.ID), strVal(acct.Name), "Batch Account", "Compute", strVal(acct.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanAppInsights(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armapplicationinsights.NewComponentsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, comp := range page.Value {
			detail := ""
			if comp.Properties != nil && comp.Properties.ApplicationType != nil {
				detail = string(*comp.Properties.ApplicationType)
			}
			result = append(result, res(strVal(comp.ID), strVal(comp.Name), "Application Insights", "Management", strVal(comp.Location), "active", detail, billableTypes))
		}
	}
	return result
}

func scanLogAnalyticsWorkspaces(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armoperationalinsights.NewWorkspacesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ws := range page.Value {
			detail := ""
			state := ""
			if ws.Properties != nil {
				if ws.Properties.SKU != nil && ws.Properties.SKU.Name != nil {
					detail = string(*ws.Properties.SKU.Name)
				}
				if ws.Properties.ProvisioningState != nil {
					state = strings.ToLower(string(*ws.Properties.ProvisioningState))
				}
			}
			result = append(result, res(strVal(ws.ID), strVal(ws.Name), "Log Analytics Workspace", "Management", strVal(ws.Location), state, detail, billableTypes))
		}
	}
	return result
}

func scanRecoveryVaults(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armrecoveryservices.NewVaultsClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vault := range page.Value {
			state := ""
			detail := ""
			if vault.Properties != nil && vault.Properties.ProvisioningState != nil {
				state = strings.ToLower(strVal(vault.Properties.ProvisioningState))
			}
			if vault.SKU != nil && vault.SKU.Name != nil {
				detail = string(*vault.SKU.Name)
			}
			result = append(result, res(strVal(vault.ID), strVal(vault.Name), "Recovery Services Vault", "Management", strVal(vault.Location), state, detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Hybrid scanners
// ---------------------------------------------------------------------------

func scanArcMachines(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID string, billableTypes map[string]bool) []scanner.Resource {
	client, err := armhybridcompute.NewMachinesClient(subID, cred, nil)
	if err != nil {
		return []scanner.Resource{}
	}
	var result []scanner.Resource
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, machine := range page.Value {
			state := ""
			detail := ""
			if machine.Properties != nil {
				if machine.Properties.Status != nil {
					state = strings.ToLower(string(*machine.Properties.Status))
				}
				if machine.Properties.OSName != nil {
					detail = strVal(machine.Properties.OSName)
				}
			}
			result = append(result, res(strVal(machine.ID), strVal(machine.Name), "Arc Machine", "Hybrid", strVal(machine.Location), state, detail, billableTypes))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resourceGroupFromID extracts the resource group name from an Azure resource ID.
// Example: /subscriptions/xxx/resourceGroups/myRG/providers/...  → "myRG"
func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
