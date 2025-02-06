#!/bin/bash

echo "Fetching AWS VPCs..."
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,State]' --output table > vpcs.txt

echo "Fetching AWS Security Groups..."
aws ec2 describe-security-groups --query "SecurityGroups[*].[GroupId, GroupName, VpcId]" --output table > security_groups.txt

echo "Fetching AWS Target Groups..."
aws elbv2 describe-target-groups --query "TargetGroups[*].[TargetGroupName, VpcId]" --output table > target_groups.txt

echo "Fetching AWS EC2 Instances and their Security Groups..."
aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId, VpcId, join(',', SecurityGroups[*].GroupId)]" --output table > ec2_instances.txt

echo "Fetching Internet Gateways..."
aws ec2 describe-internet-gateways --query "InternetGateways[*].[InternetGatewayId, Attachments[*].VpcId]" --output table > internet_gateways.txt

echo "Fetching AWS Load Balancers..."
aws elbv2 describe-load-balancers --query "LoadBalancers[*].[LoadBalancerName, VpcId, DNSName]" --output table > load_balancers.txt

# Organizing the Mapping Data
echo "-------------------------------------------------------------"
echo "AWS Network Mapping - How Traffic Flows in AWS Environment"
echo "-------------------------------------------------------------"
echo "1. **VPC Details:**"
cat vpcs.txt
echo ""

echo "2. **Security Groups and Mappings to VPCs:**"
cat security_groups.txt
echo ""

echo "3. **EC2 Instances and Their Security Groups (Mapped to VPCs):**"
cat ec2_instances.txt
echo ""

echo "4. **Target Groups (Mapped to VPCs):**"
cat target_groups.txt
echo ""

echo "5. **Internet Gateways (Mapped to VPCs):**"
cat internet_gateways.txt
echo ""

echo "6. **Load Balancers and Their Associated VPCs:**"
cat load_balancers.txt
echo ""

echo "-------------------------------------------------------------"
echo "**Traffic Flow Analysis:**"
echo "-------------------------------------------------------------"

echo "-> Internal Traffic:"
echo "   - EC2 instances communicate within the VPC using Security Groups."
echo "   - Target Groups map specific instances to a Load Balancer."
echo ""

echo "-> External Traffic:"
echo "   - Public-facing instances route traffic through an Internet Gateway."
echo "   - ALBs distribute external traffic to EC2 instances via Target Groups."
echo "   - Security Groups control access to specific ports and services."
echo ""

echo "**Summary of Traffic Flow:**"
echo "   - Internet Traffic: Internet Gateway (IGW) → ALB → EC2 Instance (with SG rules)."
echo "   - Internal Traffic: ALB → Target Group → EC2 Instance."
echo "   - Private Networks: Instances in the same VPC communicate via private IPs."
echo "-------------------------------------------------------------"

echo " Mapping completed successfully!"
