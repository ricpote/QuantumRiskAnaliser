# Throwaway test key (generated for this fixture, never used anywhere) and AWS documentation example credentials.
provider "aws" {
  region     = "eu-west-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_iam_server_certificate" "legacy" {
  name             = "legacy-cert"
  certificate_body = file("${path.module}/certs/legacy.crt")
  private_key      = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDwuAKNfd/nDUJ6FXwavlceW92YEEuCrjDzdptMpS5UWQ8NTN+J\njkhclYIvuKgdHpKiv1AxvUndpj+RdSCsNZLnlTpGEsQYCXJDtR+7pIk2cPAbIH3p\n0VyVAZvdhww2MoCIf7DpA71z4mxdG7fBCnmLLIMNY9DwsQrdhP1KfEfoUwIDAQAB\nAoGBAKCsMgf/XNP8JcMXVB8FrWC2MNKvDbfMTSA0qrQeDS5/w2w9Q3etYN9ra9ou\nhwfowDehOwX4MrWfog6U/5nyqHpfzx8b/M5f21Pct+WtKkiWRvoO06GL8p+nKB8K\nQF/9y/WNEsLLADa+Q4kgP2V6ZbYi1N6H3Mlvw7GgZAFTQsUBAkEA/KXERe9YSvlP\ntbeLTHw3s3mOSAFVgR4Fg5adpzy82GR/Gtu09yT7Ikt4EgBCJAK6yI4i2iSuw5jU\nUShkvKuXpQJBAPPpuMr7dBsdcwOlOa2KVvEPFK1Vh/S85pwgLinJO/ALQZ229bNv\n0tZCj27LIC1f3sKm0OaWPtuT7IaqkGdhvpcCQGASRO13EzMHVNk731uJTMERsxoM\nb9A2c1BTgMWsYf9DT9YNv+XPCTREUHc/4+a/pvlGm1gqZM56Ghp2asAX3AUCQQCz\nTKw7Cn1fMVbK5zpvB7LBoYRhpu46SmJ7gmxs6zDUVHH3rfcP4LPsLSGjIE6XDFKE\nZHxMBUZPw32rwNZGKOQhAkBFDYma84K0JzE3YD3BK1TvnEHGg4AMn/HcgJTF6TWr\nk9a4kOUWYZa0ClMlWV1HFMe4Tqkt8wZc0WZLltYo9ZUm\n-----END RSA PRIVATE KEY-----"
}

# same key, "hidden" with base64decode
resource "aws_iam_server_certificate" "obfuscated" {
  name             = "obfuscated-cert"
  certificate_body = file("${path.module}/certs/legacy.crt")
  private_key      = base64decode("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWFFJQkFBS0JnUUR3dUFLTmZkL25EVUo2Rlh3YXZsY2VXOTJZRUV1Q3JqRHpkcHRNcFM1VVdROE5UTitKCmpraGNsWUl2dUtnZEhwS2l2MUF4dlVuZHBqK1JkU0NzTlpMbmxUcEdFc1FZQ1hKRHRSKzdwSWsyY1BBYklIM3AKMFZ5VkFadmRod3cyTW9DSWY3RHBBNzF6NG14ZEc3ZkJDbm1MTElNTlk5RHdzUXJkaFAxS2ZFZm9Vd0lEQVFBQgpBb0dCQUtDc01nZi9YTlA4SmNNWFZCOEZyV0MyTU5LdkRiZk1UU0EwcXJRZURTNS93Mnc5UTNldFlOOXJhOW91Cmh3Zm93RGVoT3dYNE1yV2ZvZzZVLzVueXFIcGZ6eDhiL001ZjIxUGN0K1d0S2tpV1J2b08wNkdMOHArbktCOEsKUUYvOXkvV05Fc0xMQURhK1E0a2dQMlY2WmJZaTFONkgzTWx2dzdHZ1pBRlRRc1VCQWtFQS9LWEVSZTlZU3ZsUAp0YmVMVEh3M3MzbU9TQUZWZ1I0Rmc1YWRwenk4MkdSL0d0dTA5eVQ3SWt0NEVnQkNKQUs2eUk0aTJpU3V3NWpVClVTaGt2S3VYcFFKQkFQUHB1TXI3ZEJzZGN3T2xPYTJLVnZFUEZLMVZoL1M4NXB3Z0xpbkpPL0FMUVoyMjliTnYKMHRaQ2oyN0xJQzFmM3NLbTBPYVdQdHVUN0lhcWtHZGh2cGNDUUdBU1JPMTNFek1IVk5rNzMxdUpUTUVSc3hvTQpiOUEyYzFCVGdNV3NZZjlEVDlZTnYrWFBDVFJFVUhjLzQrYS9wdmxHbTFncVpNNTZHaHAyYXNBWDNBVUNRUUN6ClRLdzdDbjFmTVZiSzV6cHZCN0xCb1lSaHB1NDZTbUo3Z214czZ6RFVWSEgzcmZjUDRMUHNMU0dqSUU2WERGS0UKWkh4TUJVWlB3MzJyd05aR0tPUWhBa0JGRFltYTg0SzBKekUzWUQzQksxVHZuRUhHZzRBTW4vSGNnSlRGNlRXcgprOWE0a09VV1laYTBDbE1sV1YxSEZNZTRUcWt0OHdaYzBXWkxsdFlvOVpVbQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=")
}

# correct: key material read from a file / passed as a variable (not in the source)
resource "aws_iam_server_certificate" "from_file" {
  name             = "from-file-cert"
  certificate_body = file("${path.module}/certs/new.crt")
  private_key      = file("${path.module}/certs/new.key")
}

resource "aws_db_instance" "orders" {
  identifier = "orders"
  username   = "app"
  password   = var.db_password
}
