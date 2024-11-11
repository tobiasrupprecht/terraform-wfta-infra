# Provider configuration
provider "aws" {
  region = "us-west-2" # Set your desired AWS region here
}

# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

# Private Subnet Configuration for EKS
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a" # Set the appropriate AZ here
}

# Public Subnet Configuration for EC2 and Load Balancer
resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2a"
  map_public_ip_on_launch = true
}

# Internet Gateway for Public Subnet
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

# Public Route Table
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public_route_table.id
}

# Private Route Table for EKS (no internet access required for cluster nodes directly)
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_route_table.id
}

# Security Group for Database Server
resource "aws_security_group" "database_sg" {
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow MongoDB traffic within VPC
  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  # Allow SSH from the public internet
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Role and Policy for EC2 Instance
resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# EC2 Policy for S3 and EC2 Permissions
resource "aws_iam_policy" "s3_backup_policy" {
  name = "s3_backup_policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
        Resource = [
          aws_s3_bucket.wfta_backup_tr_bucket.arn,
          "${aws_s3_bucket.wfta_backup_tr_bucket.arn}/*"
        ]
      },
      {
        Action   = "ec2:*",
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
}

# Attach the S3 backup policy to the EC2 role
resource "aws_iam_role_policy_attachment" "s3_backup_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_backup_policy.arn
}

# Instance Profile for EC2 Instance
resource "aws_iam_instance_profile" "ec2_profile" {
  role = aws_iam_role.ec2_role.name
}

# EKS IAM Role and Policies
resource "aws_iam_role" "eks_role" {
  name = "eks_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_policy_attachment" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_service_policy_attachment" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_policy_attachment" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_iam_instance_profile" "eks_instance_profile" {
  role = aws_iam_role.eks_role.name
}

# S3 Bucket for Database Backups
resource "aws_s3_bucket" "wfta_backup_tr_bucket" {
  bucket = "my-db-backup-bucket"

  tags = {
    Name = "DatabaseBackupBucket"
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "wfta_backup_tr_bucket_block" {
  bucket = aws_s3_bucket.wfta_backup_tr_bucket.id

  block_public_acls   = false
  block_public_policy = false
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "wfta_backup_tr_bucket_versioning" {
  bucket = aws_s3_bucket.wfta_backup_tr_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Lifecycle Configuration for Backup Expiration
resource "aws_s3_bucket_lifecycle_configuration" "wfta_backup_tr_bucket_lifecycle" {
  bucket = aws_s3_bucket.wfta_backup_tr_bucket.id

  rule {
    id     = "auto-delete-old-backups"
    status = "Enabled"

    expiration {
      days = 30
    }

    filter {
      prefix = "backups/"
    }
  }
}

# Create SSH Keypair to use with EC2 instance
resource "aws_key_pair" "ssh-key" {
  key_name   = "ssh-key"
  public_key = var.public_key
}

# EC2 Instance for Database Server with Backup Functionality
resource "aws_instance" "database_server" {
  ami                         = "ami-0abcdef1234567890" # Replace with a MongoDB-compatible AMI
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.database_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
  key_name                    = "ssh-key"

  tags = {
    Name = "DatabaseServer"
  }

  # Install MongoDB, configure authentication, and set up automated backups
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update -y",
      "sudo apt-get install -y mongodb awscli",
      "sudo systemctl start mongodb",
      "sudo systemctl enable mongodb",
      # Configure MongoDB authentication
      "sudo mongo --eval 'db.createUser({user: \"admin\", pwd: \"password\", roles:[{role: \"root\", db: \"admin\"}]})'",

      # Create backup script
      "echo '#!/bin/bash' | sudo tee /usr/local/bin/mongo_backup.sh",
      "echo 'timestamp=$(date +\"%Y-%m-%d_%H-%M-%S\")' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "echo 'mongodump --username admin --password password --authenticationDatabase admin --out /tmp/mongobackup_$timestamp' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "echo 'aws s3 cp /tmp/mongobackup_$timestamp s3://${aws_s3_bucket.wfta_backup_tr_bucket.bucket}/backups/mongobackup_$timestamp --recursive' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "echo 'rm -rf /tmp/mongobackup_$timestamp' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "sudo chmod +x /usr/local/bin/mongo_backup.sh",

      # Set up a cron job to run the backup script daily at 2 AM
      "(crontab -l 2>/dev/null; echo '0 2 * * * /usr/local/bin/mongo_backup.sh') | crontab -"
    ]
  }
}

# EKS Cluster for Web Application
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "web-app-cluster"
  cluster_version = "1.21"
  vpc_id          = aws_vpc.main.id
  subnet_ids      = [aws_subnet.private.id]
  enable_irsa     = true
  iam_role_arn = aws_iam_role.eks_role.arn

  eks_managed_node_group_defaults = {
    instance_types = ["t2.micro"]
  }

  eks_managed_node_groups = {
    web_app_nodes = {
      instance_types = ["t2.micro"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }
  }
}

# Security Group for EKS LoadBalancer
resource "aws_security_group" "eks_lb_sg" {
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Kubernetes Service for Web Application
resource "kubernetes_service" "web_app" {
  metadata {
    name      = "web-app"
    namespace = "default"
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-security-groups" = aws_security_group.eks_lb_sg.id
      "service.beta.kubernetes.io/aws-load-balancer-subnets"         = aws_subnet.public.id
    }
  }

  spec {
    selector = {
      app = "web-app"
    }
    port {
      port        = 80
      target_port = 8080
    }
    type = "LoadBalancer"
  }
}

# Kubernetes Deployment for Web Application
resource "kubernetes_deployment" "web_app_deployment" {
  metadata {
    name = "web-app"
  }

  spec {
    replicas = 2
    selector {
      match_labels = {
        app = "web-app"
      }
    }
    template {
      metadata {
        labels = {
          app = "web-app"
        }
      }
      spec {
        container {
          image = "977099029806.dkr.ecr.us-west-2.amazonaws.com/wfta:0.1"
          name  = "web-app"

          # Environment variables for DB connection
          env {
            name  = "DB_HOST"
            value = aws_instance.database_server.private_ip
          }
          env {
            name  = "MONGODB_URI"
            value = "mongodb://admin:password@aws_instance.database_server.private_ip:27017"
          }
          env {
            name  = "SECRET_KEY"
            value = "secret123"
          }
          env {
            name  = "DB_USER"
            value = "admin"
          }
          env {
            name  = "DB_PASS"
            value = "password"
          }
          env {
            name  = "DB_NAME"
            value = "admin"
          }
          port {
            container_port = 8080
          }
        }
      }
    }
  }
}
