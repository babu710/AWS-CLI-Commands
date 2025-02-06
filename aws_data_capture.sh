#!/bin/bash

# Define Directories
SCRIPT_DIR="/home/centos/TEST/ALL"
TEMP_DIR="/tmp/aws_data_capture"

# Ensure Directories Exist
mkdir -p "$SCRIPT_DIR"
mkdir -p "$TEMP_DIR"

# Function to execute AWS command, capture output, and store in proper directory
run_command() {
    local CMD=$1
    local OUTPUT_FILE=$2
    local DESC=$3

    echo "Running: $CMD"
    echo "------------------------------------" >> "$OUTPUT_FILE"
    echo "📌 $DESC" >> "$OUTPUT_FILE"
    echo "------------------------------------" >> "$OUTPUT_FILE"

    # Execute command and save output, including errors
    eval "$CMD" >> "$OUTPUT_FILE" 2>> "$TEMP_DIR/aws_script_error_log.txt" || true
}

# Start Logging
echo "AWS Data Capture Script Started at $(date)" > "$TEMP_DIR/aws_script_log.txt"

# ===== IAM Users =====
run_command "aws iam list-users --query 'Users[*].[UserName,UserId]' --output table" "$SCRIPT_DIR/IAM_users.txt" "IAM Users List"

# ===== AWS Organizations Policies =====
run_command "aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[*].[Id,Name,Description]' --output table" "$SCRIPT_DIR/Organizations_policies.txt" "Organization Service Control Policies"

# ===== EC2 Network Interfaces, Gateways, Flow Logs =====
run_command "aws ec2 describe-network-interfaces --query 'NetworkInterfaces[?Attachment.InstanceId==null].[NetworkInterfaceId,Status,Description]' --output table" "$SCRIPT_DIR/EC2_network_interfaces.txt" "EC2 Network Interfaces without Instances"

run_command "aws ec2 describe-internet-gateways --query 'InternetGateways[*].[InternetGatewayId,Attachments]' --output table" "$SCRIPT_DIR/EC2_internet_gateways.txt" "EC2 Internet Gateways"

run_command "aws ec2 describe-flow-logs" "$SCRIPT_DIR/EC2_flow_logs.json" "EC2 Flow Logs (JSON Format)"

run_command "aws cloudtrail describe-trails" "$SCRIPT_DIR/CloudTrail_trails.json" "CloudTrail Trails"

# ===== EC2 Security Groups & Instances =====
run_command "aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,Description]' --output table" "$SCRIPT_DIR/EC2_security_groups.txt" "Security Groups"

run_command "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PublicIpAddress]' --output table" "$SCRIPT_DIR/EC2_instances.txt" "EC2 Instances"

# ===== S3 Buckets =====
run_command "aws s3api list-buckets --query 'Buckets[*].[Name,CreationDate]' --output table" "$SCRIPT_DIR/S3_buckets.txt" "S3 Buckets List"

# ===== RDS Instances =====
run_command "aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,DBInstanceClass,Engine,DBInstanceStatus]' --output table" "$SCRIPT_DIR/RDS_instances.txt" "RDS Instances"

# ===== Config Rules =====
run_command "aws configservice describe-config-rules --query 'ConfigRules[*].[ConfigRuleName,Source.Owner]' --output table" "$SCRIPT_DIR/Config_rules.txt" "AWS Config Rules"

# ===== AWS KMS Keys =====
run_command "aws kms list-keys --query 'Keys[*].[KeyId,KeyManager]' --output table" "$SCRIPT_DIR/KMS_keys.txt" "KMS Keys"

# ===== ELB Load Balancers =====
run_command "aws elbv2 describe-load-balancers --query 'LoadBalancers[*].[LoadBalancerName,DNSName,State.Code]' --output table" "$SCRIPT_DIR/ELB_load_balancers.txt" "Load Balancers"

# ===== EKS Clusters =====
run_command "aws eks list-clusters --query 'clusters' --output table" "$SCRIPT_DIR/EKS_clusters.txt" "EKS Clusters"

# ===== Lambda Functions =====
run_command "aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,State]' --output table" "$SCRIPT_DIR/Lambda_functions.txt" "Lambda Functions"

# ===== CloudFormation Stacks =====
run_command "aws cloudformation list-stacks --query 'StackSummaries[*].[StackName,StackStatus]' --output table" "$SCRIPT_DIR/CloudFormation_stacks.txt" "CloudFormation Stacks"

# ===== Secrets Manager =====
run_command "aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN,Description]' --output table" "$SCRIPT_DIR/Secrets_Manager.txt" "Secrets Manager Secrets"

# ===== Systems Manager Parameters =====
run_command "aws ssm describe-parameters --query 'Parameters[*].[Name,Type]' --output table" "$SCRIPT_DIR/SSM_parameters.txt" "SSM Parameters"

# ===== Auto Scaling Groups =====
run_command "aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[*].[AutoScalingGroupName,MinSize,MaxSize,DesiredCapacity]' --output table" "$SCRIPT_DIR/AutoScaling_Groups.txt" "Auto Scaling Groups"

# ===== CloudWatch Alarms =====
run_command "aws cloudwatch describe-alarms --query 'MetricAlarms[*].[AlarmName,StateValue,MetricName,Namespace]' --output table" "$SCRIPT_DIR/CloudWatch_Alarms.txt" "CloudWatch Alarms"

# ===== Route Tables (JSON & Table Format) =====
run_command "aws ec2 describe-route-tables --query 'RouteTables[*].[RouteTableId,VpcId,Routes]' --output json" "$SCRIPT_DIR/Route_Tables.json" "Route Tables in JSON Format"
run_command "aws ec2 describe-route-tables --query 'RouteTables[*].Routes[*].[DestinationCidrBlock, GatewayId]' --output table" "$SCRIPT_DIR/Route_Tables.txt" "Route Tables in Table Format"

# ===== NAT Gateways =====
run_command "aws ec2 describe-nat-gateways --query 'NatGateways[*].[NatGatewayId,VpcId,State]' --output table" "$SCRIPT_DIR/NAT_Gateways.txt" "NAT Gateways"

# End Logging
echo "AWS Data Capture Completed at $(date)" >> "$TEMP_DIR/aws_script_log.txt"

# Verify and list stored files
echo "Stored files in $SCRIPT_DIR:"
ls -al "$SCRIPT_DIR"
