resource "example_tls_policy" "legacy_gateway" {
  name               = "legacy-partner-gateway"
  minimum_protocol   = "TLSv1.0"
  key_exchange       = "ECDHE-RSA"
  certificate_family = "RSA-2048"
}
