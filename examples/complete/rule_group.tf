resource "aws_wafv2_rule_group" "rule_group" {
  description = "Certegy Rule Group"
  name        = "waf-rule-group"
  capacity    = 200
  scope       = "REGIONAL"

  rule {
    name     = "Allow-bulk-upload"
    priority = 1

    action {
      allow {
      }
    }

    statement {

      byte_match_statement {
        positional_constraint = "CONTAINS_WORD"
        search_string         = "loadConsumers"

        field_to_match {

          uri_path {}
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "loadconsumers"
      sampled_requests_enabled   = true
    }
  }
  rule {
    name     = "Geo-restriction"
    priority = 0

    action {

      block {
      }
    }

    statement {

      not_statement {
        statement {

          geo_match_statement {
            country_codes = [
              "US",
              "IN",
              "NP"
            ]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Geo-restriction"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "WAFGrp"
    sampled_requests_enabled   = true
  }
}
