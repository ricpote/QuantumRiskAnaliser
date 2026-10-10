resource "aws_lb" "public" {
  name               = "shop-public-alb"
  internal           = false
  load_balancer_type = "application"
}

resource "aws_lb" "batch" {
  name     = "batch-internal-alb"
  internal = true
}

# Legacy HTTPS listener: policy comes from a variable (variables.tf)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.legacy_tls_policy
  certificate_arn   = aws_acm_certificate.shop.arn

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/shop/abc"
  }
}

# Port 80 only redirects to HTTPS: no data in cleartext (must NOT be reported)
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Internal batch API served over plain HTTP
resource "aws_lb_listener" "batch_http" {
  load_balancer_arn = aws_lb.batch.arn
  port              = 8080
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/batch/def"
  }
}

# New listener on the AWS post-quantum policy (X25519MLKEM768)
resource "aws_lb_listener" "https_pq" {
  load_balancer_arn = aws_lb.public.arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
  certificate_arn   = aws_acm_certificate.shop.arn

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/shop/abc"
  }
}

resource "aws_acm_certificate" "shop" {
  domain_name       = "shop.example.com"
  validation_method = "DNS"
}

resource "aws_kms_key" "firmware_signing" {
  description              = "Firmware release signing key"
  customer_master_key_spec = "RSA_3072"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "orders" {
  description         = "Orders table encryption"
  enable_key_rotation = true
}

resource "aws_kms_key" "receipts_pq" {
  description              = "Receipt signing (ML-DSA)"
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
}

# resource "aws_kms_key" "old" {
#   customer_master_key_spec = "RSA_2048"
# }

resource "tls_private_key" "bastion" {
  algorithm = "ECDSA"
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled = true

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.shop.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1_2016"
  }
}
