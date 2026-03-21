package scanner

import (
	"io/fs"
	"strings"
)

// keywordToAWSTypes maps aws-billable-assets.txt keywords to resource type strings.
var keywordToAWSTypes = map[string][]string{
	"EC2":              {"EC2 Instance"},
	"RDS":              {"RDS Instance"},
	"Aurora":           {"Aurora Cluster"},
	"DynamoDB":         {"DynamoDB Table"},
	"Lambda":           {"Lambda Function"},
	"EKS":              {"EKS Cluster"},
	"ECS":              {"ECS Cluster"},
	"S3":               {"S3 Bucket"},
	"AI Models - LLMs": {"Bedrock Model"},
}

// keywordToAzureTypes maps azure-billable-assets.txt keywords to resource type strings.
var keywordToAzureTypes = map[string][]string{
	"Virtual Machine":       {"Virtual Machine", "VM Scale Set", "VM Scale Set Instance"},
	"AKS Cluster":           {"AKS Cluster"},
	"Azure Function":        {"Azure Function"},
	"SQL Database":          {"SQL Database", "SQL Managed Instance", "SQL Elastic Pool"},
	"Cosmos DB":             {"Cosmos DB"},
	"Storage Account":       {"Storage Account"},
	"Container Group":       {"Container Group"},
	"Container Registry":    {"Container Registry"},
	"Application Gateway":   {"Application Gateway"},
	"Azure Firewall":        {"Azure Firewall"},
	"NAT Gateway":           {"NAT Gateway"},
	"VNet Gateway":          {"VNet Gateway"},
	"ExpressRoute Circuit":  {"ExpressRoute Circuit"},
	"MySQL Server":          {"MySQL Server", "MySQL Flexible Server"},
	"PostgreSQL Server":     {"PostgreSQL Server", "PostgreSQL Flexible Server"},
	"MariaDB Server":        {"MariaDB Server"},
	"Redis Cache":           {"Redis Cache"},
	"Event Hub":             {"Event Hub Namespace"},
	"Service Bus":           {"Service Bus Namespace"},
	"IoT Hub":               {"IoT Hub"},
	"API Management":        {"API Management"},
	"App Service Plan":      {"App Service Plan"},
	"Synapse Workspace":     {"Synapse Workspace"},
	"Databricks Workspace":  {"Databricks Workspace"},
	"Data Factory":          {"Data Factory"},
	"HDInsight Cluster":     {"HDInsight Cluster"},
	"Data Explorer Cluster": {"Data Explorer Cluster"},
	"Cognitive Services":    {"Cognitive Services", "Azure AI Language", "Azure AI Vision", "Azure AI Speech", "Azure AI Document Intelligence", "Azure AI Content Safety"},
	"Azure OpenAI":          {"Azure OpenAI"},
	"Azure AI Services":     {"Azure AI Services"},
	"ML Workspace":          {"ML Workspace"},
	"AI Foundry Hub":        {"AI Foundry Hub"},
	"AI Foundry Project":    {"AI Foundry Project"},
	"Bot Service":           {"Bot Service"},
	"Search Service":        {"Search Service"},
	"Data Lake Store":       {"Data Lake Store"},
	"Recovery Vault":        {"Recovery Services Vault"},
	"Batch Account":         {"Batch Account"},
	"SignalR Service":       {"SignalR Service"},
	"Spring Cloud Service":  {"Spring Cloud Service"},
	"Stream Analytics Job":  {"Stream Analytics Job"},
	"Logic App":             {"Logic App"},
	"Bastion Host":          {"Bastion Host"},
}

// keywordToGCPTypes maps gcp-billable-assets.txt keywords to resource type strings.
var keywordToGCPTypes = map[string][]string{
	"Compute Instance":     {"Compute Instance"},
	"GKE Cluster":          {"GKE Cluster"},
	"Cloud Function":       {"Cloud Function"},
	"Cloud SQL Instance":   {"Cloud SQL Instance"},
	"Cloud Storage Bucket": {"Cloud Storage Bucket"},
	"Cloud Run Service":    {"Cloud Run Service"},
}

// keywordToOracleTypes maps oracle-billable-assets.txt keywords to resource type strings.
var keywordToOracleTypes = map[string][]string{
	"Compute Instance":      {"Compute Instance"},
	"Autonomous Database":   {"Autonomous Database"},
	"Object Storage Bucket": {"Object Storage Bucket"},
	"OKE Cluster":           {"OKE Cluster"},
	"MySQL Database":        {"MySQL Database"},
}

// LoadBillableTypes reads a billable-assets text file from an embedded FS
// and returns the set of resource type strings that are billable.
func LoadBillableTypes(fsys fs.FS, filename string, mapping map[string][]string) map[string]bool {
	result := map[string]bool{}
	data, err := fs.ReadFile(fsys, filename)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		kw := strings.TrimSpace(line)
		if types, ok := mapping[kw]; ok {
			for _, t := range types {
				result[t] = true
			}
		}
	}
	return result
}

// KeywordToAWSTypes returns the AWS keyword→types mapping.
func KeywordToAWSTypes() map[string][]string { return keywordToAWSTypes }

// KeywordToAzureTypes returns the Azure keyword→types mapping.
func KeywordToAzureTypes() map[string][]string { return keywordToAzureTypes }

// KeywordToGCPTypes returns the GCP keyword→types mapping.
func KeywordToGCPTypes() map[string][]string { return keywordToGCPTypes }

// KeywordToOracleTypes returns the Oracle keyword→types mapping.
func KeywordToOracleTypes() map[string][]string { return keywordToOracleTypes }
