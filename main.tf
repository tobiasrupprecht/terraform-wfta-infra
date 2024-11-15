# Provider configuration
provider "aws" {
  region = var.region # Set your desired AWS region here
}

# Define the VPC and subnets
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 3.0.0"

  name                 = "main"
  cidr                 = "10.0.0.0/16"
  azs                  = ["${var.region}a", "${var.region}b", "${var.region}c"]
  private_subnets      = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets       = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  enable_nat_gateway   = true
  enable_dns_hostnames = true
}

resource "aws_network_acl" "main" {
  vpc_id = module.vpc.vpc_id
  subnet_ids = concat(module.vpc.private_subnets, module.vpc.public_subnets)

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "main"
  }
}

# Security Group for EKS Cluster
resource "aws_security_group" "eks_sg" {
  vpc_id = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow traffic to LB
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow secured traffic from the public internet
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for Database Server
resource "aws_security_group" "database_sg" {
  vpc_id = module.vpc.vpc_id

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
    cidr_blocks = ["10.0.0.0/16"]
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
######### Unsure if I need the following section
####################################
# EKS IAM Role and Policies
#resource "aws_iam_role" "eks_role" {
#  name = "eks_role"
#
#  assume_role_policy = jsonencode({
#    Version = "2012-10-17",
#    Statement = [
#      {
#        Action = "sts:AssumeRole",
#        Effect = "Allow",
#        Principal = {
#          Service = "eks.amazonaws.com"
#        }
#      }
#    ]
#  })
#}
#
#resource "aws_iam_role_policy_attachment" "eks_policy_attachment" {
#  role       = aws_iam_role.eks_role.name
#  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
#}
#
#resource "aws_iam_role_policy_attachment" "eks_service_policy_attachment" {
#  role       = aws_iam_role.eks_role.name
#  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
#}
#
#resource "aws_iam_role_policy_attachment" "eks_vpc_policy_attachment" {
#  role       = aws_iam_role.eks_role.name
#  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
#}

#resource "aws_iam_instance_profile" "eks_instance_profile" {
#  role = aws_iam_role.eks_role.name
#}
#################### Unsure if I need the section above
#############################################################


# S3 Bucket for Database Backups
resource "aws_s3_bucket" "wfta_backup_tr_bucket" {
  bucket = "wfta-backup-bucket-tr"

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
  ami                         = "ami-066a7fbea5161f451" # Amazon Linux 2023 AMI
  instance_type               = "t2.micro"
  subnet_id                   = element(module.vpc.public_subnets, 0)
  vpc_security_group_ids      = [aws_security_group.database_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
  key_name                    = "ssh-key"

  tags = {
    Name = "DatabaseServer"
  }
  connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = var.private_key
    host        = self.public_ip
  }

  # Install MongoDB, configure authentication, and set up automated backups
  provisioner "remote-exec" {
    inline = [
      # Making everything ready to install mongodb with yum on Amazon Linux
      "echo '[mongodb-org-8.0]' | sudo tee /etc/yum.repos.d/mongodb-org-8.0.repo",
      "echo 'name=MongoDB Repository' | sudo tee -a /etc/yum.repos.d/mongodb-org-8.0.repo",
      "echo 'baseurl=https://repo.mongodb.org/yum/amazon/2023/mongodb-org/8.0/x86_64/' | sudo tee -a /etc/yum.repos.d/mongodb-org-8.0.repo",
      "echo 'gpgcheck=1' | sudo tee -a /etc/yum.repos.d/mongodb-org-8.0.repo",
      "echo 'enabled=1' | sudo tee -a /etc/yum.repos.d/mongodb-org-8.0.repo",
      "echo 'gpgkey=https://pgp.mongodb.com/server-8.0.asc' | sudo tee -a /etc/yum.repos.d/mongodb-org-8.0.repo",
      ##Install necessary dependencies for MongoDB
      ##"yum install glibc-devel",

      # Install MongoDB
      "sudo yum install -y mongodb-mongosh-shared-openssl3",
      "sudo yum install -y mongodb-org",
      # Make sure connection from outside is possible
      "sudo sed -i 's/bindIp: 127.0.0.1  # Enter 0.0.0.0,::.*/bindIp: ::,0.0.0.0/' /etc/mongod.conf",
      # Start MongoDB
      "sudo systemctl start mongod",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable mongod",
      "sudo sleep 10",
      # Configure MongoDB authentication
      "sudo mongosh --eval '\"db.createUser({user: \"admin\", pwd: \"password\", roles:[{role: \"root\", db: \"admin\"}]})\"'",

      # Create backup script
      "echo '#!/bin/bash' | sudo tee /usr/local/bin/mongo_backup.sh",
      "echo 'timestamp=$(date +\"%Y-%m-%d_%H-%M-%S\")' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "echo 'mongodump --out /tmp/mongobackup_$timestamp' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "echo 'aws s3 cp /tmp/mongobackup_$timestamp s3://${aws_s3_bucket.wfta_backup_tr_bucket.bucket}/backups/mongobackup_$timestamp --recursive' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "echo 'rm -rf /tmp/mongobackup_$timestamp' | sudo tee -a /usr/local/bin/mongo_backup.sh",
      "sudo chmod +x /usr/local/bin/mongo_backup.sh",

      # Set up a cron job to run the backup script daily at 2 AM
      #"(crontab -l 2>/dev/null; echo '0 2 * * * /usr/local/bin/mongo_backup.sh') | crontab -"
      # Set up systemd for the regular backup
      "echo '[Unit]' | sudo tee /etc/systemd/system/mongo_backup.service",
      "echo 'Description=MongoDB Backup Service' | sudo tee -a /etc/systemd/system/mongo_backup.service",
      "echo 'Wants=mongo_backup.timer' | sudo tee -a /etc/systemd/system/mongo_backup.service",
      "echo '[Service]' | sudo tee -a /etc/systemd/system/mongo_backup.service",
      "echo 'Type=oneshot' | sudo tee -a /etc/systemd/system/mongo_backup.service",
      "echo 'ExecStart=/usr/local/bin/mongo_backup.sh' | sudo tee -a /etc/systemd/system/mongo_backup.service",
      # Create timer file
      "echo '[Unit]' | sudo tee /etc/systemd/system/mongo_backup.timer",
      "echo 'Description=Run MongoDB Backup Daily at 2 AM' | sudo tee -a /etc/systemd/system/mongo_backup.timer",
      "echo '[Timer]' | sudo tee -a /etc/systemd/system/mongo_backup.timer",
      "echo 'OnCalendar=*-*-* 02:00:00' | sudo tee -a /etc/systemd/system/mongo_backup.timer",
      "echo 'Persistent=true' | sudo tee -a /etc/systemd/system/mongo_backup.timer",
      "echo '[Install]' | sudo tee -a /etc/systemd/system/mongo_backup.timer",
      "echo 'WantedBy=timers.target' | sudo tee -a /etc/systemd/system/mongo_backup.timer",
      # Enable systemd service
      "sudo systemctl daemon-reload",
      "sudo systemctl enable mongo_backup.timer",
      "sudo systemctl start mongo_backup.timer",
      "systemctl list-timers --all | grep mongo_backup"
    ]
  }
}

# EKS Cluster for Web Application
module "eks" {
  source                                   = "terraform-aws-modules/eks/aws"
  cluster_name                             = "web-app-cluster"
  cluster_version                          = "1.31"
  vpc_id                                   = module.vpc.vpc_id
  subnet_ids                               = module.vpc.private_subnets
  enable_cluster_creator_admin_permissions = true
  cluster_endpoint_public_access           = true
  authentication_mode                      = "API_AND_CONFIG_MAP"
  cluster_security_group_id                = aws_security_group.eks_sg.id 
  # create_iam_role                        = false
  # iam_role_arn                           = XYZ

  eks_managed_node_group_defaults = {
    instance_types = ["m5a.large"]
  }

  eks_managed_node_groups = {
    web_app_nodes = {
      instance_types = ["m5a.large"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }
  }
}

# Security Group for EKS LoadBalancer
resource "aws_security_group" "eks_lb_sg" {
  vpc_id = module.vpc.vpc_id

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

# Kubernetes Provider
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      module.eks.cluster_name
    ]
  }
}

# Kubernetes Service for Web Application
resource "kubernetes_service" "web_app_lb" {
  depends_on = [
    module.eks
  ]
  metadata {
    name      = "web-app-lb"
    namespace = "default"
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-security-groups" = aws_security_group.eks_lb_sg.id
      "service.beta.kubernetes.io/aws-load-balancer-subnets"         = "${element(module.vpc.public_subnets, 0)},${element(module.vpc.public_subnets, 1)}, ${element(module.vpc.public_subnets, 2)}"
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
    load_balancer_ip = null # AWS will automatically assign an external IP
    type             = "LoadBalancer"
  }
}

# Kubernetes Deployment for Web Application
resource "kubernetes_deployment" "web_app_deployment" {
  depends_on = [
    module.eks
  ]
  metadata {
    name = "web-app"
  }

  spec {
    replicas = 1
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
          image = "977099029806.dkr.ecr.us-west-2.amazonaws.com/wfta:0.4"
          name  = "web-app"

          # Environment variables for DB connection
          env {
            name  = "DB_HOST"
            value = aws_instance.database_server.private_ip
          }
          env {
            name  = "MONGODB_URI"
            value = "mongodb://admin:password@${aws_instance.database_server.private_ip}:27017"
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
