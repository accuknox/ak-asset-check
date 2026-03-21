package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/accuknox/ak-asset-check/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glacier"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	bedrockservice "github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
	"github.com/aws/smithy-go"
)

// Detect checks if AWS credentials are configured.
// Returns (configured bool, label string) where label is the AWS account ID.
func Detect() (bool, string) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return false, ""
	}
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, ""
	}
	return true, aws.ToString(identity.Account)
}

// CheckReadOnly checks if the credentials have write access using EC2 DryRun.
func CheckReadOnly(ctx context.Context) map[string]any {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return map[string]any{
			"readonly": nil,
			"enforced": false,
			"warning":  fmt.Sprintf("Could not check AWS read-only status: %v", err),
			"method":   "none",
		}
	}
	ec2Client := ec2.NewFromConfig(cfg)
	_, err = ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:  aws.String("ami-00000000"),
		MinCount: aws.Int32(1),
		MaxCount: aws.Int32(1),
		DryRun:   aws.Bool(true),
	})
	if err == nil {
		return map[string]any{
			"readonly": false,
			"enforced": false,
			"warning":  "Unexpected: DryRun did not raise.",
			"method":   "ec2-dry-run",
		}
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "DryRunOperation":
			return map[string]any{
				"readonly": false,
				"enforced": false,
				"warning":  "AWS credentials have EC2 write access. Attach the ReadOnlyAccess managed policy for safer scanning.",
				"method":   "ec2-dry-run",
			}
		case "UnauthorizedOperation":
			return map[string]any{
				"readonly": true,
				"enforced": false,
				"warning":  nil,
				"method":   "ec2-dry-run",
			}
		}
		return map[string]any{
			"readonly": true,
			"enforced": false,
			"warning":  nil,
			"method":   "ec2-dry-run",
		}
	}
	return map[string]any{
		"readonly": nil,
		"enforced": false,
		"warning":  fmt.Sprintf("Could not check AWS read-only status: %v", err),
		"method":   "none",
	}
}

func getEnabledRegions(ctx context.Context) []string {
	fallback := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return fallback
	}
	ec2Client := ec2.NewFromConfig(cfg)
	out, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("opt-in-status"),
				Values: []string{"opt-in-not-required", "opted-in"},
			},
		},
	})
	if err != nil {
		return fallback
	}
	var regions []string
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	if len(regions) == 0 {
		return fallback
	}
	return regions
}

func nameFromEC2Tags(tags []ec2types.Tag) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

func ts() string {
	return time.Now().Format("15:04:05")
}

// ── Regional scanners ────────────────────────────────────────────────────────

func scanEC2(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, r := range page.Reservations {
			for _, inst := range r.Instances {
				id := aws.ToString(inst.InstanceId)
				name := nameFromEC2Tags(inst.Tags)
				if name == "" {
					name = id
				}
				state := ""
				if inst.State != nil {
					state = string(inst.State.Name)
				}
				resources = append(resources, scanner.Resource{
					ID:       id,
					Name:     name,
					Type:     "EC2 Instance",
					Category: "Compute",
					Region:   region,
					State:    state,
					Detail:   string(inst.InstanceType),
				})
			}
		}
	}
	return resources
}

func scanEBS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vol := range page.Volumes {
			id := aws.ToString(vol.VolumeId)
			name := nameFromEC2Tags(vol.Tags)
			if name == "" {
				name = id
			}
			detail := fmt.Sprintf("%d GiB %s", aws.ToInt32(vol.Size), string(vol.VolumeType))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "EBS Volume",
				Category: "Storage",
				Region:   region,
				State:    string(vol.State),
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanSnapshots(ctx context.Context, region, accountID string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{accountID},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, snap := range page.Snapshots {
			id := aws.ToString(snap.SnapshotId)
			name := nameFromEC2Tags(snap.Tags)
			if name == "" {
				name = aws.ToString(snap.Description)
			}
			if name == "" {
				name = id
			}
			state := string(snap.State)
			detail := fmt.Sprintf("%d GiB", aws.ToInt32(snap.VolumeSize))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "EBS Snapshot",
				Category: "Storage",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanElasticIPs(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, addr := range out.Addresses {
		id := aws.ToString(addr.AllocationId)
		if id == "" {
			id = aws.ToString(addr.PublicIp)
		}
		name := aws.ToString(addr.PublicIp)
		state := "unassociated"
		detail := "Idle (billed extra)"
		if aws.ToString(addr.AssociationId) != "" {
			state = "associated"
			detail = "In use"
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     name,
			Type:     "Elastic IP",
			Category: "Networking",
			Region:   region,
			State:    state,
			Detail:   detail,
		})
	}
	return resources
}

func scanNATGateways(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeNatGatewaysPaginator(client, &ec2.DescribeNatGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, gw := range page.NatGateways {
			id := aws.ToString(gw.NatGatewayId)
			name := nameFromEC2Tags(gw.Tags)
			if name == "" {
				name = id
			}
			state := string(gw.State)
			detail := string(gw.ConnectivityType)
			if detail == "" {
				detail = "public"
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "NAT Gateway",
				Category: "Networking",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanVPNConnections(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	out, err := client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, conn := range out.VpnConnections {
		id := aws.ToString(conn.VpnConnectionId)
		name := nameFromEC2Tags(conn.Tags)
		if name == "" {
			name = id
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     name,
			Type:     "VPN Connection",
			Category: "Networking",
			Region:   region,
			State:    string(conn.State),
			Detail:   string(conn.Type),
		})
	}
	return resources
}

func scanLoadBalancers(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	var resources []scanner.Resource

	// ELBv2
	elbv2Client := elasticloadbalancingv2.NewFromConfig(cfg)
	elbv2Pager := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(elbv2Client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for elbv2Pager.HasMorePages() {
		page, err := elbv2Pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, lb := range page.LoadBalancers {
			arn := aws.ToString(lb.LoadBalancerArn)
			parts := strings.Split(arn, "/")
			id := ""
			if len(parts) >= 2 {
				id = parts[len(parts)-2] + "/" + parts[len(parts)-1]
			} else {
				id = arn
			}
			name := aws.ToString(lb.LoadBalancerName)
			state := ""
			if lb.State != nil {
				state = string(lb.State.Code)
			}
			detail := strings.ToUpper(string(lb.Type))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Load Balancer",
				Category: "Networking",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}

	// Classic ELB
	elbClient := elasticloadbalancing.NewFromConfig(cfg)
	elbPager := elasticloadbalancing.NewDescribeLoadBalancersPaginator(elbClient, &elasticloadbalancing.DescribeLoadBalancersInput{})
	for elbPager.HasMorePages() {
		page, err := elbPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, lb := range page.LoadBalancerDescriptions {
			name := aws.ToString(lb.LoadBalancerName)
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "Load Balancer",
				Category: "Networking",
				Region:   region,
				State:    "active",
				Detail:   "Classic",
			})
		}
	}
	return resources
}

func scanRDS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := rds.NewFromConfig(cfg)
	var resources []scanner.Resource

	// RDS instances
	instPager := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for instPager.HasMorePages() {
		page, err := instPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, inst := range page.DBInstances {
			id := aws.ToString(inst.DBInstanceIdentifier)
			state := aws.ToString(inst.DBInstanceStatus)
			detail := fmt.Sprintf("%s %s", aws.ToString(inst.DBInstanceClass), aws.ToString(inst.Engine))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "RDS Instance",
				Category: "Database",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}

	// Aurora clusters
	clusterPager := rds.NewDescribeDBClustersPaginator(client, &rds.DescribeDBClustersInput{})
	for clusterPager.HasMorePages() {
		page, err := clusterPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.DBClusters {
			id := aws.ToString(cluster.DBClusterIdentifier)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "Aurora Cluster",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(cluster.Status),
				Detail:   aws.ToString(cluster.Engine),
			})
		}
	}
	return resources
}

func scanDynamoDB(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := dynamodb.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, tableName := range page.TableNames {
			desc, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: aws.String(tableName),
			})
			if err != nil {
				continue
			}
			tbl := desc.Table
			state := string(tbl.TableStatus)
			detail := ""
			if tbl.BillingModeSummary != nil {
				detail = string(tbl.BillingModeSummary.BillingMode)
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(tbl.TableId),
				Name:     tableName,
				Type:     "DynamoDB Table",
				Category: "Database",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanElastiCache(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := elasticache.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := elasticache.NewDescribeCacheClustersPaginator(client, &elasticache.DescribeCacheClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.CacheClusters {
			id := aws.ToString(cluster.CacheClusterId)
			detail := fmt.Sprintf("%s %s", aws.ToString(cluster.CacheNodeType), aws.ToString(cluster.Engine))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "ElastiCache Cluster",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(cluster.CacheClusterStatus),
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanLambda(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := lambda.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fn := range page.Functions {
			name := aws.ToString(fn.FunctionName)
			detail := fmt.Sprintf("%s %dMB", string(fn.Runtime), aws.ToInt32(fn.MemorySize))
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(fn.FunctionArn),
				Name:     name,
				Type:     "Lambda Function",
				Category: "Serverless",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanEKS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := eks.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, clusterName := range page.Clusters {
			desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: aws.String(clusterName),
			})
			if err != nil {
				continue
			}
			cl := desc.Cluster
			state := string(cl.Status)
			if state == "" {
				state = "ACTIVE"
			}
			detail := fmt.Sprintf("k8s %s", aws.ToString(cl.Version))
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(cl.Arn),
				Name:     clusterName,
				Type:     "EKS Cluster",
				Category: "Containers",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanECS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ecs.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		if len(page.ClusterArns) == 0 {
			continue
		}
		desc, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: page.ClusterArns,
		})
		if err != nil {
			continue
		}
		for _, cluster := range desc.Clusters {
			arn := aws.ToString(cluster.ClusterArn)
			parts := strings.Split(arn, "/")
			name := parts[len(parts)-1]
			state := aws.ToString(cluster.Status)
			if state == "" {
				state = "ACTIVE"
			}
			detail := fmt.Sprintf("%d tasks running", cluster.RunningTasksCount)
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "ECS Cluster",
				Category: "Containers",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanECR(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ecr.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, repo := range page.Repositories {
			id := aws.ToString(repo.RepositoryArn)
			name := aws.ToString(repo.RepositoryName)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "ECR Repository",
				Category: "Containers",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanSQS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := sqs.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := sqs.NewListQueuesPaginator(client, &sqs.ListQueuesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, url := range page.QueueUrls {
			parts := strings.Split(url, "/")
			name := parts[len(parts)-1]
			detail := "Standard"
			if strings.HasSuffix(name, ".fifo") {
				detail = "FIFO"
			}
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "SQS Queue",
				Category: "Messaging",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanSNS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := sns.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := sns.NewListTopicsPaginator(client, &sns.ListTopicsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, topic := range page.Topics {
			arn := aws.ToString(topic.TopicArn)
			parts := strings.Split(arn, ":")
			name := parts[len(parts)-1]
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "SNS Topic",
				Category: "Messaging",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanAPIGateway(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	var resources []scanner.Resource

	// REST APIs
	restClient := apigateway.NewFromConfig(cfg)
	restPager := apigateway.NewGetRestApisPaginator(restClient, &apigateway.GetRestApisInput{})
	for restPager.HasMorePages() {
		page, err := restPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, api := range page.Items {
			id := aws.ToString(api.Id)
			name := aws.ToString(api.Name)
			detail := ""
			if api.EndpointConfiguration != nil && len(api.EndpointConfiguration.Types) > 0 {
				detail = string(api.EndpointConfiguration.Types[0])
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "API Gateway REST",
				Category: "API",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}

	// HTTP/WS APIs (v2) — no SDK paginator; use NextToken manually
	v2Client := apigatewayv2.NewFromConfig(cfg)
	v2Input := &apigatewayv2.GetApisInput{}
	for {
		page, err := v2Client.GetApis(ctx, v2Input)
		if err != nil {
			break
		}
		for _, api := range page.Items {
			id := aws.ToString(api.ApiId)
			name := aws.ToString(api.Name)
			proto := string(api.ProtocolType)
			if proto == "" {
				proto = "HTTP"
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     fmt.Sprintf("API Gateway %s", proto),
				Category: "API",
				Region:   region,
				State:    "active",
				Detail:   proto,
			})
		}
		if page.NextToken == nil {
			break
		}
		v2Input.NextToken = page.NextToken
	}
	return resources
}

func scanSecretsManager(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := secretsmanager.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, secret := range page.SecretList {
			id := aws.ToString(secret.ARN)
			name := aws.ToString(secret.Name)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Secrets Manager Secret",
				Category: "Security",
				Region:   region,
				State:    "active",
				Detail:   "$0.40/month",
			})
		}
	}
	return resources
}

func scanRedshift(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := redshift.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := redshift.NewDescribeClustersPaginator(client, &redshift.DescribeClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.Clusters {
			id := aws.ToString(cluster.ClusterIdentifier)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "Redshift Cluster",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(cluster.ClusterStatus),
				Detail:   aws.ToString(cluster.NodeType),
			})
		}
	}
	return resources
}

func scanBedrock(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := bedrockservice.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Foundation models
	fmOut, err := client.ListFoundationModels(ctx, &bedrockservice.ListFoundationModelsInput{})
	if err == nil {
		for _, model := range fmOut.ModelSummaries {
			modelID := aws.ToString(model.ModelId)
			name := aws.ToString(model.ModelName)
			if name == "" {
				name = modelID
			}
			state := "active"
			if model.ModelLifecycle != nil {
				state = strings.ToLower(string(model.ModelLifecycle.Status))
			}
			var modalities []string
			for _, m := range model.InputModalities {
				modalities = append(modalities, string(m))
			}
			detail := fmt.Sprintf("%s · %v", aws.ToString(model.ProviderName), modalities)
			resources = append(resources, scanner.Resource{
				ID:       modelID,
				Name:     name,
				Type:     "Bedrock Model",
				Category: "AI / ML",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}

	// Custom models
	cmPager := bedrockservice.NewListCustomModelsPaginator(client, &bedrockservice.ListCustomModelsInput{})
	for cmPager.HasMorePages() {
		page, err := cmPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, model := range page.ModelSummaries {
			arn := aws.ToString(model.ModelArn)
			parts := strings.Split(arn, "/")
			id := parts[len(parts)-1]
			name := aws.ToString(model.ModelName)
			detail := fmt.Sprintf("Custom · base: %s", aws.ToString(model.BaseModelArn))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Bedrock Model",
				Category: "AI / ML",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanAutoscalingGroups(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := autoscaling.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, &autoscaling.DescribeAutoScalingGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, group := range page.AutoScalingGroups {
			name := aws.ToString(group.AutoScalingGroupName)
			detail := fmt.Sprintf("min=%d max=%d desired=%d",
				aws.ToInt32(group.MinSize),
				aws.ToInt32(group.MaxSize),
				aws.ToInt32(group.DesiredCapacity))
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "Auto Scaling Group",
				Category: "Compute",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanTransitGateways(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeTransitGatewaysPaginator(client, &ec2.DescribeTransitGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, tgw := range page.TransitGateways {
			id := aws.ToString(tgw.TransitGatewayId)
			name := nameFromEC2Tags(tgw.Tags)
			if name == "" {
				name = id
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Transit Gateway",
				Category: "Networking",
				Region:   region,
				State:    string(tgw.State),
				Detail:   "",
			})
		}
	}
	return resources
}

func scanInternetGateways(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeInternetGatewaysPaginator(client, &ec2.DescribeInternetGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, igw := range page.InternetGateways {
			id := aws.ToString(igw.InternetGatewayId)
			name := nameFromEC2Tags(igw.Tags)
			if name == "" {
				name = id
			}
			state := "detached"
			for _, att := range igw.Attachments {
				if string(att.State) == "available" {
					state = "attached"
					break
				}
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "Internet Gateway",
				Category: "Networking",
				Region:   region,
				State:    state,
				Detail:   "",
			})
		}
	}
	return resources
}

func scanVPCEndpoints(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ec2.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ec2.NewDescribeVpcEndpointsPaginator(client, &ec2.DescribeVpcEndpointsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ep := range page.VpcEndpoints {
			id := aws.ToString(ep.VpcEndpointId)
			name := nameFromEC2Tags(ep.Tags)
			if name == "" {
				svc := aws.ToString(ep.ServiceName)
				parts := strings.Split(svc, ".")
				name = parts[len(parts)-1]
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "VPC Endpoint",
				Category: "Networking",
				Region:   region,
				State:    string(ep.State),
				Detail:   string(ep.VpcEndpointType),
			})
		}
	}
	return resources
}

func scanEFS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := efs.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := efs.NewDescribeFileSystemsPaginator(client, &efs.DescribeFileSystemsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fs := range page.FileSystems {
			id := aws.ToString(fs.FileSystemId)
			name := aws.ToString(fs.Name)
			if name == "" {
				name = id
			}
			sizeGiB := int64(0)
			if fs.SizeInBytes != nil {
				sizeGiB = fs.SizeInBytes.Value / (1024 * 1024 * 1024)
			}
			detail := fmt.Sprintf("%d GiB · %s", sizeGiB, string(fs.PerformanceMode))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "EFS File System",
				Category: "Storage",
				Region:   region,
				State:    string(fs.LifeCycleState),
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanFSx(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := fsx.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := fsx.NewDescribeFileSystemsPaginator(client, &fsx.DescribeFileSystemsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fs := range page.FileSystems {
			id := aws.ToString(fs.FileSystemId)
			name := id
			for _, tag := range fs.Tags {
				if aws.ToString(tag.Key) == "Name" {
					name = aws.ToString(tag.Value)
					break
				}
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "FSx File System",
				Category: "Storage",
				Region:   region,
				State:    strings.ToLower(string(fs.Lifecycle)),
				Detail:   string(fs.FileSystemType),
			})
		}
	}
	return resources
}

func scanGlacier(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := glacier.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := glacier.NewListVaultsPaginator(client, &glacier.ListVaultsInput{
		AccountId: aws.String("-"),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vault := range page.VaultList {
			name := aws.ToString(vault.VaultName)
			detail := fmt.Sprintf("%d archives", vault.NumberOfArchives)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(vault.VaultARN),
				Name:     name,
				Type:     "Glacier Vault",
				Category: "Storage",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanDAX(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := dax.NewFromConfig(cfg)
	var resources []scanner.Resource
	out, err := client.DescribeClusters(ctx, &dax.DescribeClustersInput{})
	if err != nil {
		return nil
	}
	for _, cluster := range out.Clusters {
		name := aws.ToString(cluster.ClusterName)
		resources = append(resources, scanner.Resource{
			ID:       aws.ToString(cluster.ClusterArn),
			Name:     name,
			Type:     "DAX Cluster",
			Category: "Database",
			Region:   region,
			State:    aws.ToString(cluster.Status),
			Detail:   aws.ToString(cluster.NodeType),
		})
	}
	return resources
}

func scanDocDB(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := docdb.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := docdb.NewDescribeDBClustersPaginator(client, &docdb.DescribeDBClustersInput{
		Filters: []docdbtypes.Filter{
			{Name: aws.String("engine"), Values: []string{"docdb"}},
		},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.DBClusters {
			id := aws.ToString(cluster.DBClusterIdentifier)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "DocumentDB Cluster",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(cluster.Status),
				Detail:   aws.ToString(cluster.EngineVersion),
			})
		}
	}
	return resources
}

func scanOpenSearch(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := opensearch.NewFromConfig(cfg)
	listOut, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, domain := range listOut.DomainNames {
		name := aws.ToString(domain.DomainName)
		desc, err := client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: aws.String(name),
		})
		if err != nil {
			continue
		}
		state := "active"
		if aws.ToBool(desc.DomainStatus.Deleted) {
			state = "deleted"
		}
		resources = append(resources, scanner.Resource{
			ID:       aws.ToString(desc.DomainStatus.ARN),
			Name:     name,
			Type:     "OpenSearch Domain",
			Category: "Database",
			Region:   region,
			State:    state,
			Detail:   aws.ToString(desc.DomainStatus.EngineVersion),
		})
	}
	return resources
}

func scanElasticsearch(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := elasticsearchservice.NewFromConfig(cfg)
	listOut, err := client.ListDomainNames(ctx, &elasticsearchservice.ListDomainNamesInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, domain := range listOut.DomainNames {
		name := aws.ToString(domain.DomainName)
		desc, err := client.DescribeElasticsearchDomain(ctx, &elasticsearchservice.DescribeElasticsearchDomainInput{
			DomainName: aws.String(name),
		})
		if err != nil {
			continue
		}
		state := "active"
		if aws.ToBool(desc.DomainStatus.Deleted) {
			state = "deleted"
		}
		resources = append(resources, scanner.Resource{
			ID:       aws.ToString(desc.DomainStatus.ARN),
			Name:     name,
			Type:     "Elasticsearch Domain",
			Category: "Database",
			Region:   region,
			State:    state,
			Detail:   aws.ToString(desc.DomainStatus.ElasticsearchVersion),
		})
	}
	return resources
}

func scanNeptune(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := neptune.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := neptune.NewDescribeDBClustersPaginator(client, &neptune.DescribeDBClustersInput{
		Filters: []neptunetypes.Filter{
			{Name: aws.String("engine"), Values: []string{"neptune"}},
		},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.DBClusters {
			id := aws.ToString(cluster.DBClusterIdentifier)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "Neptune Cluster",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(cluster.Status),
				Detail:   aws.ToString(cluster.EngineVersion),
			})
		}
	}
	return resources
}

func scanMemoryDB(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := memorydb.NewFromConfig(cfg)
	out, err := client.DescribeClusters(ctx, &memorydb.DescribeClustersInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, cluster := range out.Clusters {
		name := aws.ToString(cluster.Name)
		resources = append(resources, scanner.Resource{
			ID:       aws.ToString(cluster.ARN),
			Name:     name,
			Type:     "MemoryDB Cluster",
			Category: "Database",
			Region:   region,
			State:    aws.ToString(cluster.Status),
			Detail:   aws.ToString(cluster.NodeType),
		})
	}
	return resources
}

func scanRedshiftServerless(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := redshiftserverless.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Namespaces
	nsPager := redshiftserverless.NewListNamespacesPaginator(client, &redshiftserverless.ListNamespacesInput{})
	for nsPager.HasMorePages() {
		page, err := nsPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ns := range page.Namespaces {
			name := aws.ToString(ns.NamespaceName)
			state := strings.ToLower(string(ns.Status))
			if state == "" {
				state = "available"
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(ns.NamespaceArn),
				Name:     name,
				Type:     "Redshift Serverless Namespace",
				Category: "Database",
				Region:   region,
				State:    state,
				Detail:   "",
			})
		}
	}

	// Workgroups
	wgPager := redshiftserverless.NewListWorkgroupsPaginator(client, &redshiftserverless.ListWorkgroupsInput{})
	for wgPager.HasMorePages() {
		page, err := wgPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, wg := range page.Workgroups {
			name := aws.ToString(wg.WorkgroupName)
			state := strings.ToLower(string(wg.Status))
			if state == "" {
				state = "available"
			}
			detail := fmt.Sprintf("%d RPU", aws.ToInt32(wg.BaseCapacity))
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(wg.WorkgroupArn),
				Name:     name,
				Type:     "Redshift Serverless Workgroup",
				Category: "Database",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanKinesisStreams(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := kinesis.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := kinesis.NewListStreamsPaginator(client, &kinesis.ListStreamsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, summary := range page.StreamSummaries {
			name := aws.ToString(summary.StreamName)
			desc, err := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{
				StreamName: aws.String(name),
			})
			state := "active"
			detail := ""
			if err == nil && desc.StreamDescriptionSummary != nil {
				state = strings.ToLower(string(desc.StreamDescriptionSummary.StreamStatus))
				detail = fmt.Sprintf("%d shards", desc.StreamDescriptionSummary.OpenShardCount)
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(summary.StreamARN),
				Name:     name,
				Type:     "Kinesis Stream",
				Category: "Messaging",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanKinesisFirehose(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := firehose.NewFromConfig(cfg)
	var resources []scanner.Resource
	var startName *string
	for {
		page, err := client.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{
			ExclusiveStartDeliveryStreamName: startName,
		})
		if err != nil {
			break
		}
		for _, streamName := range page.DeliveryStreamNames {
			desc, err := client.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{
				DeliveryStreamName: aws.String(streamName),
			})
			if err != nil {
				continue
			}
			d := desc.DeliveryStreamDescription
			state := strings.ToLower(string(d.DeliveryStreamStatus))
			detail := string(d.DeliveryStreamType)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(d.DeliveryStreamARN),
				Name:     streamName,
				Type:     "Kinesis Firehose",
				Category: "Messaging",
				Region:   region,
				State:    state,
				Detail:   detail,
			})
		}
		if !aws.ToBool(page.HasMoreDeliveryStreams) || len(page.DeliveryStreamNames) == 0 {
			break
		}
		startName = aws.String(page.DeliveryStreamNames[len(page.DeliveryStreamNames)-1])
	}
	return resources
}

func scanMSK(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := kafka.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := kafka.NewListClustersPaginator(client, &kafka.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.ClusterInfoList {
			arn := aws.ToString(cluster.ClusterArn)
			parts := strings.Split(arn, "/")
			id := parts[len(parts)-1]
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     aws.ToString(cluster.ClusterName),
				Type:     "MSK Cluster",
				Category: "Messaging",
				Region:   region,
				State:    strings.ToLower(string(cluster.State)),
				Detail:   "",
			})
		}
	}
	return resources
}

func scanMQ(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := mq.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := mq.NewListBrokersPaginator(client, &mq.ListBrokersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, broker := range page.BrokerSummaries {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(broker.BrokerId),
				Name:     aws.ToString(broker.BrokerName),
				Type:     "MQ Broker",
				Category: "Messaging",
				Region:   region,
				State:    strings.ToLower(string(broker.BrokerState)),
				Detail:   string(broker.EngineType),
			})
		}
	}
	return resources
}

func scanACM(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := acm.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cert := range page.CertificateSummaryList {
			arn := aws.ToString(cert.CertificateArn)
			parts := strings.Split(arn, "/")
			id := parts[len(parts)-1]
			name := aws.ToString(cert.DomainName)
			state := strings.ToLower(string(cert.Status))
			if state == "" {
				state = "issued"
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "ACM Certificate",
				Category: "Security",
				Region:   region,
				State:    state,
				Detail:   name,
			})
		}
	}
	return resources
}

func scanKMS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := kms.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, key := range page.Keys {
			keyID := aws.ToString(key.KeyId)
			desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: aws.String(keyID),
			})
			if err != nil {
				continue
			}
			meta := desc.KeyMetadata
			if string(meta.KeyManager) == "AWS" {
				continue
			}
			name := aws.ToString(meta.Description)
			if name == "" {
				name = keyID
			}
			resources = append(resources, scanner.Resource{
				ID:       keyID,
				Name:     name,
				Type:     "KMS Key",
				Category: "Security",
				Region:   region,
				State:    strings.ToLower(string(meta.KeyState)),
				Detail:   string(meta.KeyUsage),
			})
		}
	}
	return resources
}

func scanGuardDuty(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := guardduty.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := guardduty.NewListDetectorsPaginator(client, &guardduty.ListDetectorsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, detectorID := range page.DetectorIds {
			desc, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
				DetectorId: aws.String(detectorID),
			})
			if err != nil {
				continue
			}
			state := strings.ToLower(string(desc.Status))
			if state == "" {
				state = "enabled"
			}
			resources = append(resources, scanner.Resource{
				ID:       detectorID,
				Name:     fmt.Sprintf("Detector · %s", region),
				Type:     "GuardDuty Detector",
				Category: "Security",
				Region:   region,
				State:    state,
				Detail:   "",
			})
		}
	}
	return resources
}

func scanWAFv2Regional(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := wafv2.NewFromConfig(cfg)
	var resources []scanner.Resource
	var nextMarker *string
	for {
		out, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope:      wafv2types.ScopeRegional,
			NextMarker: nextMarker,
			Limit:      aws.Int32(100),
		})
		if err != nil {
			break
		}
		for _, acl := range out.WebACLs {
			name := aws.ToString(acl.Name)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(acl.Id),
				Name:     name,
				Type:     "WAF Web ACL (Regional)",
				Category: "Security",
				Region:   region,
				State:    "active",
				Detail:   "Regional",
			})
		}
		nextMarker = out.NextMarker
		if nextMarker == nil {
			break
		}
	}
	return resources
}

func scanNetworkFirewall(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := networkfirewall.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := networkfirewall.NewListFirewallsPaginator(client, &networkfirewall.ListFirewallsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fw := range page.Firewalls {
			name := aws.ToString(fw.FirewallName)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(fw.FirewallArn),
				Name:     name,
				Type:     "Network Firewall",
				Category: "Security",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanCloudFormation(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := cloudformation.NewFromConfig(cfg)
	var resources []scanner.Resource
	activeStatuses := map[string]bool{
		"CREATE_COMPLETE":              true,
		"UPDATE_COMPLETE":              true,
		"ROLLBACK_COMPLETE":            true,
		"UPDATE_ROLLBACK_COMPLETE":     true,
		"IMPORT_COMPLETE":              true,
	}
	paginator := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, stack := range page.Stacks {
			statusStr := string(stack.StackStatus)
			if !activeStatuses[statusStr] {
				continue
			}
			name := aws.ToString(stack.StackName)
			state := strings.ToLower(strings.ReplaceAll(statusStr, "_", "-"))
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(stack.StackId),
				Name:     name,
				Type:     "CloudFormation Stack",
				Category: "Management",
				Region:   region,
				State:    state,
				Detail:   "",
			})
		}
	}
	return resources
}

func scanCloudTrail(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := cloudtrail.NewFromConfig(cfg)
	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, trail := range out.TrailList {
		arn := aws.ToString(trail.TrailARN)
		parts := strings.Split(arn, "/")
		id := parts[len(parts)-1]
		name := aws.ToString(trail.Name)

		statusOut, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: aws.String(arn),
		})
		state := "stopped"
		if err == nil && aws.ToBool(statusOut.IsLogging) {
			state = "logging"
		}
		detail := "Single-region"
		if aws.ToBool(trail.IsMultiRegionTrail) {
			detail = "Multi-region"
		}
		resources = append(resources, scanner.Resource{
			ID:       id,
			Name:     name,
			Type:     "CloudTrail Trail",
			Category: "Management",
			Region:   region,
			State:    state,
			Detail:   detail,
		})
	}
	return resources
}

func scanBackup(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := backup.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Vaults
	vaultPager := backup.NewListBackupVaultsPaginator(client, &backup.ListBackupVaultsInput{})
	for vaultPager.HasMorePages() {
		page, err := vaultPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vault := range page.BackupVaultList {
			name := aws.ToString(vault.BackupVaultName)
			detail := fmt.Sprintf("%d recovery points", vault.NumberOfRecoveryPoints)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(vault.BackupVaultArn),
				Name:     name,
				Type:     "Backup Vault",
				Category: "Management",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}

	// Plans
	planPager := backup.NewListBackupPlansPaginator(client, &backup.ListBackupPlansInput{})
	for planPager.HasMorePages() {
		page, err := planPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, plan := range page.BackupPlansList {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(plan.BackupPlanId),
				Name:     aws.ToString(plan.BackupPlanName),
				Type:     "Backup Plan",
				Category: "Management",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanCodeBuild(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := codebuild.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := codebuild.NewListProjectsPaginator(client, &codebuild.ListProjectsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, name := range page.Projects {
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "CodeBuild Project",
				Category: "Developer Tools",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanCodeCommit(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := codecommit.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := codecommit.NewListRepositoriesPaginator(client, &codecommit.ListRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, repo := range page.Repositories {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(repo.RepositoryId),
				Name:     aws.ToString(repo.RepositoryName),
				Type:     "CodeCommit Repository",
				Category: "Developer Tools",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanCodePipeline(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := codepipeline.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := codepipeline.NewListPipelinesPaginator(client, &codepipeline.ListPipelinesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pipeline := range page.Pipelines {
			name := aws.ToString(pipeline.Name)
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "CodePipeline",
				Category: "Developer Tools",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanCodeDeploy(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := codedeploy.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := codedeploy.NewListApplicationsPaginator(client, &codedeploy.ListApplicationsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, appName := range page.Applications {
			resources = append(resources, scanner.Resource{
				ID:       appName,
				Name:     appName,
				Type:     "CodeDeploy Application",
				Category: "Developer Tools",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanEMR(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := emr.NewFromConfig(cfg)
	stateFilters := []emrtypes.ClusterState{
		emrtypes.ClusterStateStarting,
		emrtypes.ClusterStateBootstrapping,
		emrtypes.ClusterStateRunning,
		emrtypes.ClusterStateWaiting,
	}
	var resources []scanner.Resource
	var marker *string
	for {
		page, err := client.ListClusters(ctx, &emr.ListClustersInput{
			ClusterStates: stateFilters,
			Marker:        marker,
		})
		if err != nil {
			break
		}
		for _, cluster := range page.Clusters {
			state := ""
			if cluster.Status != nil {
				state = strings.ToLower(string(cluster.Status.State))
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(cluster.Id),
				Name:     aws.ToString(cluster.Name),
				Type:     "EMR Cluster",
				Category: "Analytics",
				Region:   region,
				State:    state,
				Detail:   "",
			})
		}
		marker = page.Marker
		if marker == nil {
			break
		}
	}
	return resources
}

func scanGlue(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := glue.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Jobs
	jobPager := glue.NewGetJobsPaginator(client, &glue.GetJobsInput{})
	for jobPager.HasMorePages() {
		page, err := jobPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, job := range page.Jobs {
			name := aws.ToString(job.Name)
			detail := ""
			if job.Command != nil {
				detail = aws.ToString(job.Command.Name)
			}
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "Glue Job",
				Category: "Analytics",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}

	// Crawlers
	crawlerPager := glue.NewGetCrawlersPaginator(client, &glue.GetCrawlersInput{})
	for crawlerPager.HasMorePages() {
		page, err := crawlerPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, crawler := range page.Crawlers {
			name := aws.ToString(crawler.Name)
			state := strings.ToLower(string(crawler.State))
			if state == "" {
				state = "ready"
			}
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "Glue Crawler",
				Category: "Analytics",
				Region:   region,
				State:    state,
				Detail:   "",
			})
		}
	}
	return resources
}

func scanAthena(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := athena.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := athena.NewListWorkGroupsPaginator(client, &athena.ListWorkGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, wg := range page.WorkGroups {
			name := aws.ToString(wg.Name)
			if name == "primary" {
				continue
			}
			resources = append(resources, scanner.Resource{
				ID:       name,
				Name:     name,
				Type:     "Athena Workgroup",
				Category: "Analytics",
				Region:   region,
				State:    strings.ToLower(string(wg.State)),
				Detail:   "",
			})
		}
	}
	return resources
}

func scanTimestream(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := timestreamwrite.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := timestreamwrite.NewListDatabasesPaginator(client, &timestreamwrite.ListDatabasesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, db := range page.Databases {
			name := aws.ToString(db.DatabaseName)
			detail := fmt.Sprintf("%d tables", db.TableCount)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(db.Arn),
				Name:     name,
				Type:     "Timestream Database",
				Category: "Analytics",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanSageMaker(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := sagemaker.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Notebooks
	nbPager := sagemaker.NewListNotebookInstancesPaginator(client, &sagemaker.ListNotebookInstancesInput{})
	for nbPager.HasMorePages() {
		page, err := nbPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, nb := range page.NotebookInstances {
			name := aws.ToString(nb.NotebookInstanceName)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(nb.NotebookInstanceArn),
				Name:     name,
				Type:     "SageMaker Notebook",
				Category: "AI / ML",
				Region:   region,
				State:    strings.ToLower(string(nb.NotebookInstanceStatus)),
				Detail:   string(nb.InstanceType),
			})
		}
	}

	// Domains
	domainPager := sagemaker.NewListDomainsPaginator(client, &sagemaker.ListDomainsInput{})
	for domainPager.HasMorePages() {
		page, err := domainPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, domain := range page.Domains {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(domain.DomainId),
				Name:     aws.ToString(domain.DomainName),
				Type:     "SageMaker Domain",
				Category: "AI / ML",
				Region:   region,
				State:    strings.ToLower(string(domain.Status)),
				Detail:   "",
			})
		}
	}

	// Endpoints
	epPager := sagemaker.NewListEndpointsPaginator(client, &sagemaker.ListEndpointsInput{})
	for epPager.HasMorePages() {
		page, err := epPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ep := range page.Endpoints {
			name := aws.ToString(ep.EndpointName)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(ep.EndpointArn),
				Name:     name,
				Type:     "SageMaker Endpoint",
				Category: "AI / ML",
				Region:   region,
				State:    strings.ToLower(string(ep.EndpointStatus)),
				Detail:   "",
			})
		}
	}
	return resources
}

func scanAppSync(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := appsync.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := appsync.NewListGraphqlApisPaginator(client, &appsync.ListGraphqlApisInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, api := range page.GraphqlApis {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(api.ApiId),
				Name:     aws.ToString(api.Name),
				Type:     "AppSync API",
				Category: "API",
				Region:   region,
				State:    "active",
				Detail:   string(api.AuthenticationType),
			})
		}
	}
	return resources
}

func scanCognito(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	var resources []scanner.Resource

	// User Pools
	cipClient := cognitoidentityprovider.NewFromConfig(cfg)
	upPager := cognitoidentityprovider.NewListUserPoolsPaginator(cipClient, &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int32(60),
	})
	for upPager.HasMorePages() {
		page, err := upPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pool := range page.UserPools {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(pool.Id),
				Name:     aws.ToString(pool.Name),
				Type:     "Cognito User Pool",
				Category: "Identity",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}

	// Identity Pools
	ciClient := cognitoidentity.NewFromConfig(cfg)
	ipPager := cognitoidentity.NewListIdentityPoolsPaginator(ciClient, &cognitoidentity.ListIdentityPoolsInput{
		MaxResults: aws.Int32(60),
	})
	for ipPager.HasMorePages() {
		page, err := ipPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, pool := range page.IdentityPools {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(pool.IdentityPoolId),
				Name:     aws.ToString(pool.IdentityPoolName),
				Type:     "Cognito Identity Pool",
				Category: "Identity",
				Region:   region,
				State:    "active",
				Detail:   "",
			})
		}
	}
	return resources
}

func scanSFN(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := sfn.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := sfn.NewListStateMachinesPaginator(client, &sfn.ListStateMachinesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, sm := range page.StateMachines {
			arn := aws.ToString(sm.StateMachineArn)
			parts := strings.Split(arn, ":")
			id := parts[len(parts)-1]
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     aws.ToString(sm.Name),
				Type:     "Step Functions State Machine",
				Category: "Serverless",
				Region:   region,
				State:    "active",
				Detail:   string(sm.Type),
			})
		}
	}
	return resources
}

func scanSES(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ses.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := ses.NewListIdentitiesPaginator(client, &ses.ListIdentitiesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, identity := range page.Identities {
			detail := "domain"
			if strings.Contains(identity, "@") {
				detail = "email"
			}
			resources = append(resources, scanner.Resource{
				ID:       identity,
				Name:     identity,
				Type:     "SES Identity",
				Category: "Application",
				Region:   region,
				State:    "active",
				Detail:   detail,
			})
		}
	}
	return resources
}

func scanLightsail(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := lightsail.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Instances — Lightsail has no SDK paginator; use PageToken manually
	instInput := &lightsail.GetInstancesInput{}
	for {
		page, err := client.GetInstances(ctx, instInput)
		if err != nil {
			break
		}
		for _, inst := range page.Instances {
			name := aws.ToString(inst.Name)
			state := ""
			if inst.State != nil {
				state = aws.ToString(inst.State.Name)
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(inst.Arn),
				Name:     name,
				Type:     "Lightsail Instance",
				Category: "Compute",
				Region:   region,
				State:    state,
				Detail:   aws.ToString(inst.BundleId),
			})
		}
		if page.NextPageToken == nil {
			break
		}
		instInput.PageToken = page.NextPageToken
	}

	// Buckets
	bucketsOut, err := client.GetBuckets(ctx, &lightsail.GetBucketsInput{})
	if err == nil {
		for _, bucket := range bucketsOut.Buckets {
			name := aws.ToString(bucket.Name)
			state := "active"
			if bucket.State != nil {
				state = aws.ToString(bucket.State.Code)
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(bucket.Arn),
				Name:     name,
				Type:     "Lightsail Bucket",
				Category: "Storage",
				Region:   region,
				State:    state,
				Detail:   aws.ToString(bucket.BundleId),
			})
		}
	}
	return resources
}

func scanTransfer(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := transfer.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := transfer.NewListServersPaginator(client, &transfer.ListServersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, server := range page.Servers {
			id := aws.ToString(server.ServerId)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "Transfer Server",
				Category: "Application",
				Region:   region,
				State:    strings.ToLower(string(server.State)),
				Detail:   string(server.EndpointType),
			})
		}
	}
	return resources
}

func scanWorkspaces(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := workspaces.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := workspaces.NewDescribeWorkspacesPaginator(client, &workspaces.DescribeWorkspacesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ws := range page.Workspaces {
			id := aws.ToString(ws.WorkspaceId)
			name := aws.ToString(ws.UserName)
			if name == "" {
				name = id
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "WorkSpace",
				Category: "Application",
				Region:   region,
				State:    strings.ToLower(string(ws.State)),
				Detail:   aws.ToString(ws.BundleId),
			})
		}
	}
	return resources
}

func scanDMS(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := databasemigrationservice.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := databasemigrationservice.NewDescribeReplicationInstancesPaginator(client, &databasemigrationservice.DescribeReplicationInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, inst := range page.ReplicationInstances {
			id := aws.ToString(inst.ReplicationInstanceIdentifier)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     id,
				Type:     "DMS Replication Instance",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(inst.ReplicationInstanceStatus),
				Detail:   aws.ToString(inst.ReplicationInstanceClass),
			})
		}
	}
	return resources
}

func scanElasticBeanstalk(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := elasticbeanstalk.NewFromConfig(cfg)
	out, err := client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, env := range out.Environments {
		platform := aws.ToString(env.PlatformArn)
		platformParts := strings.Split(platform, "/")
		platform = platformParts[len(platformParts)-1]
		detail := fmt.Sprintf("%s · %s", aws.ToString(env.ApplicationName), platform)
		resources = append(resources, scanner.Resource{
			ID:       aws.ToString(env.EnvironmentId),
			Name:     aws.ToString(env.EnvironmentName),
			Type:     "Elastic Beanstalk Environment",
			Category: "Compute",
			Region:   region,
			State:    strings.ToLower(string(env.Status)),
			Detail:   detail,
		})
	}
	return resources
}

func scanECSServices(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := ecs.NewFromConfig(cfg)
	var resources []scanner.Resource

	clusterPager := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	for clusterPager.HasMorePages() {
		clusterPage, err := clusterPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, clusterArn := range clusterPage.ClusterArns {
			svcPager := ecs.NewListServicesPaginator(client, &ecs.ListServicesInput{
				Cluster: aws.String(clusterArn),
			})
			for svcPager.HasMorePages() {
				svcPage, err := svcPager.NextPage(ctx)
				if err != nil {
					break
				}
				if len(svcPage.ServiceArns) == 0 {
					continue
				}
				descOut, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{
					Cluster:  aws.String(clusterArn),
					Services: svcPage.ServiceArns,
				})
				if err != nil {
					continue
				}
				for _, svc := range descOut.Services {
					name := aws.ToString(svc.ServiceName)
					state := strings.ToLower(aws.ToString(svc.Status))
					if state == "" {
						state = "active"
					}
					detail := fmt.Sprintf("%d/%d tasks", svc.RunningCount, svc.DesiredCount)
					resources = append(resources, scanner.Resource{
						ID:       aws.ToString(svc.ServiceArn),
						Name:     name,
						Type:     "ECS Service",
						Category: "Containers",
						Region:   region,
						State:    state,
						Detail:   detail,
					})
				}
			}
		}
	}
	return resources
}

func scanEKSNodeGroups(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := eks.NewFromConfig(cfg)
	var resources []scanner.Resource

	clusterPager := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})
	for clusterPager.HasMorePages() {
		clusterPage, err := clusterPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, clusterName := range clusterPage.Clusters {
			ngPager := eks.NewListNodegroupsPaginator(client, &eks.ListNodegroupsInput{
				ClusterName: aws.String(clusterName),
			})
			for ngPager.HasMorePages() {
				ngPage, err := ngPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, ngName := range ngPage.Nodegroups {
					desc, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
						ClusterName:   aws.String(clusterName),
						NodegroupName: aws.String(ngName),
					})
					if err != nil {
						continue
					}
					ng := desc.Nodegroup
					state := strings.ToLower(string(ng.Status))
					if state == "" {
						state = "active"
					}
					instanceType := ""
					if len(ng.InstanceTypes) > 0 {
						instanceType = ng.InstanceTypes[0]
					}
					detail := fmt.Sprintf("%s · %s", clusterName, instanceType)
					resources = append(resources, scanner.Resource{
						ID:       aws.ToString(ng.NodegroupArn),
						Name:     ngName,
						Type:     "EKS Node Group",
						Category: "Containers",
						Region:   region,
						State:    state,
						Detail:   detail,
					})
				}
			}
		}
	}
	return resources
}

func scanElastiCacheReplicationGroups(ctx context.Context, region string) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil
	}
	client := elasticache.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := elasticache.NewDescribeReplicationGroupsPaginator(client, &elasticache.DescribeReplicationGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, rg := range page.ReplicationGroups {
			id := aws.ToString(rg.ReplicationGroupId)
			name := aws.ToString(rg.Description)
			if name == "" {
				name = id
			}
			detail := fmt.Sprintf("%d nodes", len(rg.MemberClusters))
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "ElastiCache Replication Group",
				Category: "Database",
				Region:   region,
				State:    aws.ToString(rg.Status),
				Detail:   detail,
			})
		}
	}
	return resources
}

// ── Global scanners ──────────────────────────────────────────────────────────

func scanS3(ctx context.Context) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil
	}
	client := s3.NewFromConfig(cfg)
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil
	}
	var resources []scanner.Resource
	for _, bucket := range out.Buckets {
		name := aws.ToString(bucket.Name)
		region := "us-east-1"
		locOut, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(name),
		})
		if err == nil {
			loc := string(locOut.LocationConstraint)
			if loc != "" {
				region = loc
			}
		}
		detail := ""
		if bucket.CreationDate != nil {
			detail = fmt.Sprintf("Created %s", bucket.CreationDate.Format("2006-01-02"))
		}
		resources = append(resources, scanner.Resource{
			ID:       name,
			Name:     name,
			Type:     "S3 Bucket",
			Category: "Storage",
			Region:   region,
			State:    "active",
			Detail:   detail,
			Cloud:    "aws",
		})
	}
	return resources
}

func scanCloudFront(ctx context.Context) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil
	}
	client := cloudfront.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		if page.DistributionList == nil {
			continue
		}
		for _, dist := range page.DistributionList.Items {
			id := aws.ToString(dist.Id)
			name := aws.ToString(dist.Comment)
			if name == "" {
				name = aws.ToString(dist.DomainName)
			}
			state := strings.ToLower(aws.ToString(dist.Status))
			detail := aws.ToString(dist.DomainName)
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     name,
				Type:     "CloudFront Distribution",
				Category: "Networking",
				Region:   "global",
				State:    state,
				Detail:   detail,
				Cloud:    "aws",
			})
		}
	}
	return resources
}

func scanRoute53(ctx context.Context) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil
	}
	client := route53.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, zone := range page.HostedZones {
			zoneID := aws.ToString(zone.Id)
			parts := strings.Split(zoneID, "/")
			id := parts[len(parts)-1]
			detail := "Public"
			if zone.Config != nil && zone.Config.PrivateZone {
				detail = "Private"
			}
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     aws.ToString(zone.Name),
				Type:     "Route53 Hosted Zone",
				Category: "Networking",
				Region:   "global",
				State:    "active",
				Detail:   detail,
				Cloud:    "aws",
			})
		}
	}
	return resources
}

func scanIAM(ctx context.Context) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil
	}
	client := iam.NewFromConfig(cfg)
	var resources []scanner.Resource

	// Users
	userPager := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPager.HasMorePages() {
		page, err := userPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, user := range page.Users {
			detail := ""
			if user.CreateDate != nil {
				detail = fmt.Sprintf("Created %s", user.CreateDate.Format("2006-01-02"))
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(user.UserId),
				Name:     aws.ToString(user.UserName),
				Type:     "IAM User",
				Category: "Identity",
				Region:   "global",
				State:    "active",
				Detail:   detail,
				Cloud:    "aws",
			})
		}
	}

	// Roles
	rolePager := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePager.HasMorePages() {
		page, err := rolePager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, role := range page.Roles {
			if strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/") {
				continue
			}
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(role.RoleId),
				Name:     aws.ToString(role.RoleName),
				Type:     "IAM Role",
				Category: "Identity",
				Region:   "global",
				State:    "active",
				Detail:   aws.ToString(role.Description),
				Cloud:    "aws",
			})
		}
	}

	// Groups
	groupPager := iam.NewListGroupsPaginator(client, &iam.ListGroupsInput{})
	for groupPager.HasMorePages() {
		page, err := groupPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, group := range page.Groups {
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(group.GroupId),
				Name:     aws.ToString(group.GroupName),
				Type:     "IAM Group",
				Category: "Identity",
				Region:   "global",
				State:    "active",
				Detail:   "",
				Cloud:    "aws",
			})
		}
	}
	return resources
}

func scanGlobalAccelerator(ctx context.Context) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		return nil
	}
	client := globalaccelerator.NewFromConfig(cfg)
	var resources []scanner.Resource
	paginator := globalaccelerator.NewListAcceleratorsPaginator(client, &globalaccelerator.ListAcceleratorsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, acc := range page.Accelerators {
			arn := aws.ToString(acc.AcceleratorArn)
			parts := strings.Split(arn, "/")
			id := parts[len(parts)-1]
			resources = append(resources, scanner.Resource{
				ID:       id,
				Name:     aws.ToString(acc.Name),
				Type:     "Global Accelerator",
				Category: "Networking",
				Region:   "global",
				State:    strings.ToLower(string(acc.Status)),
				Detail:   aws.ToString(acc.DnsName),
				Cloud:    "aws",
			})
		}
	}
	return resources
}

func scanWAF(ctx context.Context) []scanner.Resource {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil
	}
	client := wafv2.NewFromConfig(cfg)
	var resources []scanner.Resource
	var nextMarker *string
	for {
		out, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope:      wafv2types.ScopeCloudfront,
			NextMarker: nextMarker,
			Limit:      aws.Int32(100),
		})
		if err != nil {
			break
		}
		for _, acl := range out.WebACLs {
			name := aws.ToString(acl.Name)
			resources = append(resources, scanner.Resource{
				ID:       aws.ToString(acl.Id),
				Name:     name,
				Type:     "WAF Web ACL",
				Category: "Security",
				Region:   "global",
				State:    "active",
				Detail:   "CloudFront scope",
				Cloud:    "aws",
			})
		}
		nextMarker = out.NextMarker
		if nextMarker == nil {
			break
		}
	}
	return resources
}

// ── Scan orchestration ───────────────────────────────────────────────────────

// Scan runs the AWS scan and appends results to state.
func Scan(ctx context.Context, state *scanner.ScanState, billableTypes map[string]bool, mode string) {
	now := ts()

	// Load config and get account ID
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		state.AddLog(now, fmt.Sprintf("AWS: failed to load config: %v", err), "err")
		return
	}
	stsClient := sts.NewFromConfig(cfg)
	identityOut, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	accountID := ""
	if err == nil {
		accountID = aws.ToString(identityOut.Account)
	}

	state.AddLog(ts(), "AWS: discovering regions…", "info")
	regions := getEnabledRegions(ctx)
	state.AddLog(ts(), fmt.Sprintf("AWS: scanning %d regions", len(regions)), "info")

	// Global scanners
	state.AddLog(ts(), "AWS: scanning global resources…", "info")

	globalFuncs := []func(context.Context) []scanner.Resource{
		scanS3,
		scanCloudFront,
		scanRoute53,
		scanWAF,
		scanIAM,
		scanGlobalAccelerator,
	}
	for _, fn := range globalFuncs {
		resources := fn(ctx)
		for i := range resources {
			resources[i].Cloud = "aws"
			resources[i].Billable = billableTypes[resources[i].Type]
		}
		if len(resources) > 0 {
			state.AddResources(resources)
		}
	}

	// Regional scanners
	type regionalFn func(context.Context, string) []scanner.Resource

	regionalScanners := []regionalFn{
		scanEC2,
		scanEBS,
		scanElasticIPs,
		scanNATGateways,
		scanVPNConnections,
		scanLoadBalancers,
		scanRDS,
		scanDynamoDB,
		scanElastiCache,
		scanLambda,
		scanEKS,
		scanECS,
		scanECR,
		scanSQS,
		scanSNS,
		scanAPIGateway,
		scanSecretsManager,
		scanRedshift,
		scanBedrock,
		scanAutoscalingGroups,
		scanElasticBeanstalk,
		scanLightsail,
		scanTransitGateways,
		scanInternetGateways,
		scanVPCEndpoints,
		scanNetworkFirewall,
		scanEFS,
		scanFSx,
		scanGlacier,
		scanDAX,
		scanDocDB,
		scanOpenSearch,
		scanElasticsearch,
		scanNeptune,
		scanMemoryDB,
		scanRedshiftServerless,
		scanElastiCacheReplicationGroups,
		scanDMS,
		scanTimestream,
		scanKinesisStreams,
		scanKinesisFirehose,
		scanMSK,
		scanMQ,
		scanACM,
		scanKMS,
		scanGuardDuty,
		scanWAFv2Regional,
		scanCloudFormation,
		scanCloudTrail,
		scanBackup,
		scanCodeBuild,
		scanCodeCommit,
		scanCodePipeline,
		scanCodeDeploy,
		scanEMR,
		scanGlue,
		scanAthena,
		scanSageMaker,
		scanAppSync,
		scanSES,
		scanTransfer,
		scanWorkspaces,
		scanCognito,
		scanSFN,
		scanECSServices,
		scanEKSNodeGroups,
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, region := range regions {
		region := region
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			state.AddLog(ts(), fmt.Sprintf("AWS: scanning region %s", region), "dim")

			var regionResources []scanner.Resource

			// Snapshot scanner needs accountID
			snaps := scanSnapshots(ctx, region, accountID)
			regionResources = append(regionResources, snaps...)

			for _, fn := range regionalScanners {
				resources := fn(ctx, region)
				regionResources = append(regionResources, resources...)
			}

			for i := range regionResources {
				regionResources[i].Cloud = "aws"
				regionResources[i].Billable = billableTypes[regionResources[i].Type]
			}

			if len(regionResources) > 0 {
				state.AddResources(regionResources)
			}
		}()
	}

	wg.Wait()
	state.AddLog(ts(), "AWS: scan complete", "ok")
}
