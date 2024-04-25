resource "aws_cloudwatch_log_group" "this" {
  count             = var.is_create_logging_configuration ? 1 : 0
  name              = format("aws-waf-logs-%s", var.name)
  retention_in_days = var.cloudwatch_log_retention_in_days
  kms_key_id        = var.cloudwatch_log_kms_key_id
  tags = merge(
    local.tags,
    { "Name" = format("aws-waf-logs-%s", var.name) }
  )
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count = var.is_create_logging_configuration ? 1 : 0

  log_destination_configs = var.use_cloudwatch_logs ? [aws_cloudwatch_log_group.this[0].arn] : var.use_firehose_logs ? [var.firehose_arn] : []
  resource_arn            = aws_wafv2_web_acl.this.arn

  dynamic "redacted_fields" {
    for_each = var.redacted_fields
    content {
      dynamic "single_header" {
        for_each = length(lookup(redacted_fields.value, "single_header", {})) == 0 ? [] : [lookup(redacted_fields.value, "single_header", {})]
        content {
          name = lookup(single_header.value, "name", null)
        }
      }

      dynamic "single_query_argument" {
        for_each = length(lookup(redacted_fields.value, "single_query_argument", {})) == 0 ? [] : [lookup(redacted_fields.value, "single_query_argument", {})]
        content {
          name = lookup(single_query_argument.value, "name", null)
        }
      }
    }
  }

  dynamic "logging_filter" {
    for_each = length(var.logging_filter) == 0 ? [] : [var.logging_filter]
    content {
      default_behavior = lookup(logging_filter.value, "default_behavior", "KEEP")

      dynamic "filter" {
        for_each = length(lookup(logging_filter.value, "filter", {})) == 0 ? [] : toset(logging_filter.value["filter"])
        content {
          behavior    = filter.value["behavior"]
          requirement = lookup(filter.value, "requirement", "MEETS_ANY")

          dynamic "condition" {
            for_each = length(lookup(filter.value, "condition", {})) == 0 ? [] : toset(filter.value["condition"])
            content {
              dynamic "action_condition" {
                for_each = length(lookup(condition.value, "action_condition", {})) == 0 ? [] : [lookup(condition.value, "action_condition", {})]
                content {
                  action = action_condition.value["action"]
                }
              }

              dynamic "label_name_condition" {
                for_each = length(lookup(condition.value, "label_name_condition", {})) == 0 ? [] : [lookup(condition.value, "label_name_condition", {})]
                content {
                  label_name = label_name_condition.value["label_name"]
                }
              }
            }
          }
        }
      }
    }
  }
}
