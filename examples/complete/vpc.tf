######
# VPC
resource "aws_vpc" "my_vpc" {
  # checkov:skip=CKV2_AWS_12: Ensure AWS Default Security Group restricts all traffic
  # checkov:skip=CKV2_AWS_11: Ensure AWS VPC Flow logs are enabled
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "MyVPC"
  }
}
###IGW####
resource "aws_internet_gateway" "my_igw" {
  vpc_id = aws_vpc.my_vpc.id

}
# Subnets
resource "aws_subnet" "subnet_1" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "subnet-1"
  }
}

resource "aws_subnet" "subnet_2" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "subnet-2"
  }
}

# Security Group
resource "aws_security_group" "my_security_group" {
  # checkov:skip=CKV2_AWS_5: Ensure Security Groups are attached to EC2 instances or ENIs
  # checkov:skip=CKV_AWS_260: Ensure Security Groups do not allow ingress
  # checkov:skip=CKV_AWS_23: Ensure Route53 A Record has an attached resource

  name        = "my-security-group"
  description = "My Security Group"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "my-security-group"
  }
}
