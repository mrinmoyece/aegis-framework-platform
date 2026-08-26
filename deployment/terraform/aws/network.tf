resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_subnet" "private" {
  for_each = local.private_subnet_cidrs

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false

  tags = {
    Name                              = "${var.name}-private-${each.key}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "data" {
  for_each = local.data_subnet_cidrs

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-data-${each.key}" }
}

resource "aws_subnet" "public" {
  for_each = local.public_subnet_cidrs

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false

  tags = {
    Name                     = "${var.name}-public-${each.key}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_eip" "nat" {
  for_each = aws_subnet.public
  domain   = "vpc"

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  for_each = aws_subnet.public

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
}

resource "aws_route" "private" {
  for_each = aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route_table_association" "data" {
  for_each = aws_subnet.data

  subnet_id      = each.value.id
  route_table_id = aws_route_table.data.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = concat(
    [for table in aws_route_table.private : table.id],
    [aws_route_table.data.id],
  )
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name}-endpoints-"
  description = "TLS from private application subnets to interface endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = values(local.private_subnet_cidrs)
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_vpc_endpoint" "aws_services" {
  for_each = toset([
    "ecr.api",
    "ecr.dkr",
    "kms",
    "logs",
    "secretsmanager",
    "sts",
  ])

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = values(aws_subnet.private)[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}

resource "aws_security_group" "temporal" {
  name_prefix = "${var.name}-temporal-"
  description = "Temporal Cloud PrivateLink frontend"
  vpc_id      = aws_vpc.this.id

  ingress {
    protocol    = "tcp"
    from_port   = 7233
    to_port     = 7233
    cidr_blocks = values(local.private_subnet_cidrs)
  }

  egress {
    protocol    = "tcp"
    from_port   = 7233
    to_port     = 7233
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_vpc_endpoint" "temporal" {
  vpc_id              = aws_vpc.this.id
  service_name        = var.temporal_private_service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = values(aws_subnet.private)[*].id
  security_group_ids  = [aws_security_group.temporal.id]
  private_dns_enabled = false

  tags = {
    Name               = "${var.name}-temporal"
    TemporalServerName = var.temporal_server_name
  }
}

resource "aws_route53_zone" "temporal_private" {
  name = var.temporal_private_zone_name

  vpc {
    vpc_id = aws_vpc.this.id
  }
}

resource "aws_route53_record" "temporal_private" {
  zone_id = aws_route53_zone.temporal_private.zone_id
  name    = var.temporal_server_name
  type    = "CNAME"
  ttl     = 60
  records = [tolist(aws_vpc_endpoint.temporal.dns_entry)[0].dns_name]
}
