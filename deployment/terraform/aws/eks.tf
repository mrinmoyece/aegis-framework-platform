resource "aws_iam_role" "eks_cluster" {
  name                 = "${var.name}-eks-cluster"
  permissions_boundary = var.permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.telemetry.arn
}

resource "aws_security_group" "workloads" {
  name_prefix = "${var.name}-workloads-"
  description = "Shared EKS workload node identity"
  vpc_id      = aws_vpc.this.id

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_eks_cluster" "this" {
  name     = var.name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.20.0.0/16"
  }

  vpc_config {
    subnet_ids              = values(aws_subnet.private)[*].id
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.workloads.id]
  }

  encryption_config {
    provider { key_arn = aws_kms_key.data.arn }
    resources = ["secrets"]
  }

  depends_on = [
    aws_cloudwatch_log_group.eks,
    aws_iam_role_policy_attachment.eks_cluster,
  ]
}

resource "aws_eks_access_entry" "administrator" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.eks_admin_principal_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "administrator" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.administrator.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope { type = "cluster" }
}

resource "aws_iam_role" "eks_nodes" {
  name                 = "${var.name}-eks-nodes"
  permissions_boundary = var.permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_nodes" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
  ])

  role       = aws_iam_role.eks_nodes.name
  policy_arn = each.value
}

resource "aws_launch_template" "system" {
  name_prefix            = "${var.name}-system-"
  update_default_version = true
  vpc_security_group_ids = [
    aws_eks_cluster.this.vpc_config[0].cluster_security_group_id,
    aws_security_group.workloads.id,
  ]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted   = true
      kms_key_id  = aws_kms_key.data.arn
      volume_size = 100
      volume_type = "gp3"
    }
  }
}

resource "aws_launch_template" "sandbox" {
  name_prefix            = "${var.name}-sandbox-"
  update_default_version = true
  image_id               = var.sandbox_ami_id
  vpc_security_group_ids = [
    aws_eks_cluster.this.vpc_config[0].cluster_security_group_id,
    aws_security_group.workloads.id,
  ]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted   = true
      kms_key_id  = aws_kms_key.data.arn
      volume_size = 200
      volume_type = "gp3"
    }
  }

  user_data = base64encode(<<-EOT
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="aegis-node"

    --aegis-node
    Content-Type: application/node.eks.aws

    ---
    apiVersion: node.eks.aws/v1alpha1
    kind: NodeConfig
    spec:
      cluster:
        name: ${aws_eks_cluster.this.name}
        apiServerEndpoint: ${aws_eks_cluster.this.endpoint}
        certificateAuthority: ${aws_eks_cluster.this.certificate_authority[0].data}
        cidr: ${aws_eks_cluster.this.kubernetes_network_config[0].service_ipv4_cidr}
    --aegis-node--
  EOT
  )
}

resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = values(aws_subnet.private)[*].id
  capacity_type   = "ON_DEMAND"
  instance_types  = ["m7g.xlarge"]
  ami_type        = "AL2023_ARM_64_STANDARD"
  version         = var.kubernetes_version

  launch_template {
    id      = aws_launch_template.system.id
    version = aws_launch_template.system.latest_version
  }

  scaling_config {
    desired_size = 6
    min_size     = 3
    max_size     = 30
  }

  update_config { max_unavailable = 1 }

  labels = { "aegis.io/node-pool" = "system" }

  depends_on = [
    aws_eks_addon.vpc_cni,
    aws_iam_role_policy_attachment.eks_nodes,
  ]
}

resource "aws_eks_node_group" "sandbox" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "sandbox-kata"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = values(aws_subnet.private)[*].id
  capacity_type   = "ON_DEMAND"
  instance_types  = ["m7i.2xlarge"]

  launch_template {
    id      = aws_launch_template.sandbox.id
    version = aws_launch_template.sandbox.latest_version
  }

  scaling_config {
    desired_size = 3
    min_size     = 3
    max_size     = 20
  }

  update_config { max_unavailable = 1 }

  labels = {
    "aegis.io/node-pool"       = "sandbox"
    "aegis.io/sandbox-runtime" = "kata"
  }

  taint {
    key    = "aegis.io/sandbox"
    value  = "true"
    effect = "NO_SCHEDULE"
  }

  depends_on = [
    aws_eks_addon.vpc_cni,
    aws_iam_role_policy_attachment.eks_nodes,
  ]
}

resource "aws_eks_addon" "pod_identity" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "eks-pod-identity-agent"
  addon_version               = var.pod_identity_addon_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  addon_version               = var.vpc_cni_addon_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
  })
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "kube-proxy"
  addon_version               = var.kube_proxy_addon_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  addon_version               = var.coredns_addon_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_iam_role" "workload" {
  for_each = local.workload_service_accounts

  name                 = "${var.name}-${each.key}"
  permissions_boundary = var.permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_eks_pod_identity_association" "workload" {
  for_each = local.workload_service_accounts

  cluster_name    = aws_eks_cluster.this.name
  namespace       = "aegis-system"
  service_account = each.value
  role_arn        = aws_iam_role.workload[each.key].arn

  depends_on = [aws_eks_addon.pod_identity]
}
