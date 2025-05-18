provider "aws" {
  region = "us-east-1"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", "demo"]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", "demo"]
      command     = "aws"
    }
  }
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# VPC
resource "aws_vpc" "my_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = "my_vpc"
  }
}

# Subnets (Public)
resource "aws_subnet" "my_subnet_1" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  tags = {
    Name = "vm_subnet_public"
    "kubernetes.io/role/elb"     = "1" #this instruct the kubernetes to create public load balancer in these subnets
    "kubernetes.io/cluster/demo" = "owned"
  }
}

# Subnets (Public)
resource "aws_subnet" "my_subnet_1c" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1c"
  map_public_ip_on_launch = true
  tags = {
    Name = "second_subnet_public"
    "kubernetes.io/role/elb"     = "1" #this instruct the kubernetes to create public load balancer in these subnets
    "kubernetes.io/cluster/demo" = "owned"
  }
}
# Subnet in us-east-1b (private)
resource "aws_subnet" "subnet_us_east_1b_private" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false  # Private subnet

  tags = {
    Name = "subnet_us_east_1b_private"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/cluster/demo"      = "owned"
  }
}
# Subnet in us-east-1c (private)
resource "aws_subnet" "subnet_us_east_1c_private" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1c"
  map_public_ip_on_launch = false  # Private subnet

  tags = {
    Name = "subnet_us_east_1c_private"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/cluster/demo"      = "owned"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "my_igw" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "my_igw"
  }
}

# Route Table
resource "aws_route_table" "my_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.my_igw.id
  }
}

# routing table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.my_vpc.id

  route {
      cidr_block                 = "0.0.0.0/0"
      nat_gateway_id             = aws_nat_gateway.k8s-nat.id
    }

  tags = {
    Name = "private"
  }
}

# Associate the route table with the subnet
resource "aws_route_table_association" "my_subnet_association" {
  subnet_id      = aws_subnet.my_subnet_1.id
  route_table_id = aws_route_table.my_route_table.id
}

# Associate the route table with the subnet
resource "aws_route_table_association" "public-subnet-us-east-1b" {
  subnet_id      = aws_subnet.my_subnet_1c.id
  route_table_id = aws_route_table.my_route_table.id
}

resource "aws_route_table_association" "private-us-east-1b" {
  subnet_id      = aws_subnet.subnet_us_east_1b_private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private-us-east-1c" {
  subnet_id      = aws_subnet.subnet_us_east_1c_private.id
  route_table_id = aws_route_table.private.id
}


# Security Group for EC2 Instance
resource "aws_security_group" "ec2_sg" {
  name        = "ec2_sg"
  description = "Security group for EC2 instance"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 27017
    to_port   = 27017
    protocol  = "tcp"
    cidr_blocks = ["10.0.2.0/24", "10.0.3.0/24"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
   }
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2_permissive_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
      Name = "EC2 IAM Role"
  }
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "test_policy"
  role = aws_iam_role.ec2_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*",
        "ec2:*",
        "iam:*",
        "eks:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_key_pair" "ssh_keypair" {
  key_name   = "jimmyc-keypair"
  public_key = file("./id_ed25519.pub")
}
# EC2 Instance
resource "aws_instance" "my_instance" {
  ami             = "ami-055744c75048d8296" # Ubuntu 18.04 LTS
  instance_type   = "t2.micro"
  key_name        = aws_key_pair.ssh_keypair.key_name
  subnet_id       = aws_subnet.my_subnet_1.id
  vpc_security_group_ids  = [aws_security_group.ec2_sg.id]
  associate_public_ip_address = true
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install gnupg curl
              curl -fsSL https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
              echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
              apt-get update
              apt-get install -y mongodb-org
              systemctl start mongod
              systemctl enable mongodb
              EOF
 tags = {
    Name = "mg-db-server"

 }
}

resource "aws_s3_bucket" "db_backup_bucket" {
  bucket = "db-backup-bucket-05162025"
}

resource "aws_s3_bucket_ownership_controls" "db_backup_bucket" {
  bucket = aws_s3_bucket.db_backup_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "db_backup_bucket" {
  bucket = aws_s3_bucket.db_backup_bucket.id

  block_public_acls   = false
  block_public_policy = false
}

resource "aws_s3_bucket_acl" "db_backup_bucket" {
  bucket = aws_s3_bucket.db_backup_bucket.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.db_backup_bucket,
    aws_s3_bucket_public_access_block.db_backup_bucket,
  ]
}

data "aws_iam_policy_document" "s3_bucket_db_backup" {
  policy_id = "s3_bucket_db_backup"

  statement {
    actions = [
      "s3:GetObject"
    ]
    effect = "Allow"
    resources = [
      "${aws_s3_bucket.db_backup_bucket.arn}/*"
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    sid = "S3IconsBucketPublicAccess"
  }
}

resource "aws_s3_bucket_policy" "foo_icons" {
  bucket = aws_s3_bucket.db_backup_bucket.id
  policy = data.aws_iam_policy_document.s3_bucket_db_backup.json
}

resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "nat"
  }
}

resource "aws_nat_gateway" "k8s-nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.my_subnet_1.id

  tags = {
    Name = "k8s-nat"
  }

  depends_on = [aws_internet_gateway.my_igw]
}

# IAM role for eks

resource "aws_iam_role" "demo" {
  name = "eks-cluster-demo"
  tags = {
    tag-key = "eks-cluster-demo"
  }

  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "eks.amazonaws.com"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
}

# eks policy attachment

resource "aws_iam_role_policy_attachment" "demo-AmazonEKSClusterPolicy" {
  role       = aws_iam_role.demo.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_security_group" "eks" {
    name        = "tasky-app eks cluster"
    description = "Allow traffic"
    vpc_id      = aws_vpc.my_vpc.id

    ingress {
      description      = "World"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }

    egress {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }

    tags = {
       Name = "EKS tasky",
       "kubernetes.io/cluster/demo": "owned"
    }
  }

module "eks" {
    source = "terraform-aws-modules/eks/aws"
    version = "18.19.0"

    cluster_name                    = "demo"
    cluster_version                 = "1.27"
    cluster_endpoint_private_access = true
    cluster_endpoint_public_access  = true
    cluster_additional_security_group_ids = [aws_security_group.eks.id]

    vpc_id     = aws_vpc.my_vpc.id
    subnet_ids = [
        aws_subnet.subnet_us_east_1b_private.id,
        aws_subnet.subnet_us_east_1c_private.id
    ]

    eks_managed_node_group_defaults = {
      ami_type               = "AL2_x86_64"
      disk_size              = 50
      instance_types         = ["t2.small", "t2.small"]
      vpc_security_group_ids = [aws_security_group.eks.id]
    }

    eks_managed_node_groups = {
      green = {
        min_size     = 1
        max_size     = 1
        desired_size = 1

        instance_types = ["t2.small"]
        capacity_type  = "SPOT"
        # labels = "tasky-app"
        taints = {
        }
        tags = {
            Name = "tasky-node"
        }
      }
    }

    tags = {
        Name = "tasky-eks-cluster"
    }
  }

# role for nodegroup

resource "aws_iam_role" "nodes" {
  name = "eks-node-group-nodes"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# IAM policy attachment to nodegroup

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}

module "lb_role" {
 source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

 role_name                              = "tasky_app_eks_lb"
 attach_load_balancer_controller_policy = true

 oidc_providers = {
     main = {
     provider_arn               = module.eks.oidc_provider_arn
     namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
     }
 }
 }

 resource "kubernetes_service_account" "service-account" {
  metadata {
      name      = "aws-load-balancer-controller"
      namespace = "kube-system"
      labels = {
      "app.kubernetes.io/name"      = "aws-load-balancer-controller"
      "app.kubernetes.io/component" = "controller"
      }
      annotations = {
      "eks.amazonaws.com/role-arn"               = module.lb_role.iam_role_arn
      "eks.amazonaws.com/sts-regional-endpoints" = "true"
      }
  }
  }

  resource "helm_release" "alb-controller" {
   name       = "aws-load-balancer-controller"
   repository = "https://aws.github.io/eks-charts"
   chart      = "aws-load-balancer-controller"
   namespace  = "kube-system"
   depends_on = [
       kubernetes_service_account.service-account
   ]

   set {
       name  = "region"
       value = "us-east-1"
   }

   set {
       name  = "vpcId"
       value = aws_vpc.my_vpc.id
   }

   set {
       name  = "image.repository"
       value = "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon/aws-load-balancer-controller"
   }

   set {
       name  = "serviceAccount.create"
       value = "false"
   }

   set {
       name  = "serviceAccount.name"
       value = "aws-load-balancer-controller"
   }

   set {
       name  = "clusterName"
       value = "demo"
   }
   }