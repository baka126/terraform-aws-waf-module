variable "name" {
  type        = string
  description = "A friendly name of the WebACL."
}

variable "scope" {
  type        = string
  description = <<-DOC
    Specifies whether this is for an AWS CloudFront distribution or for a regional application.
    Possible values are `CLOUDFRONT` or `REGIONAL`.
    To work with CloudFront, you must also specify the region us-east-1 (N. Virginia) on the AWS provider.
  DOC
  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "Allowed values: `CLOUDFRONT`, `REGIONAL`."
  }
}

variable "is_enable_default_rule" {
  type        = bool
  description = "If true with enable default rule (detail in locals.tf)"
  default     = true
}

# https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
variable "managed_rules" {
  type = list(object({
    name            = string
    priority        = number
    override_action = string
    excluded_rules  = list(string)
    rule_action_override = list(object({
      name          = string
      action_to_use = string
    }))
  }))
  description = "List of Managed WAF rules."
  default     = []
}

variable "ip_sets_rule" {
  # List of object need to have consis structure --> cv to any --> and make good description
  type = list(object({
    name               = string
    priority           = number
    ip_set             = list(string)
    action             = string
    ip_address_version = string
  }))
  description = "A rule to detect web requests coming from particular IP addresses or address ranges."
  default     = []
}

variable "ip_set" {
  description = <<EOL
  To create IP set ex.
  ip_sets = {
    "baka-vpn-ipv4-set" = {
      ip_addresses       = ["127.0.01/32"]
      ip_address_version = "IPV4"
    },
    "baka-vpn-ipv6-set" = {
      ip_addresses       = ["2403:6200:88a2:a6f8:2096:9b42:31f8:61fd/128"]
      ip_address_version = "IPV6"
    }
  }
  EOL
  type = map(object({
    ip_addresses       = list(string)
    ip_address_version = string
  }))
  default = {}
}

variable "custom_rules" {
  description = "Find the example for these structure"
  type        = any
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "A mapping of tags to assign to the WAFv2 ACL."
  default     = {}
}

variable "association_resources" {
  type        = list(string)
  description = "ARN of the ALB, CloudFront, Etc to be associated with the WAFv2 ACL."
  default     = []
}

variable "default_action" {
  type        = string
  description = "The action to perform if none of the rules contained in the WebACL match."
  default     = "block"

  validation {
    condition     = var.default_action == "block" || var.default_action == "allow"
    error_message = "The default action must be either 'block' or 'allow'."
  }
}

variable "is_enable_cloudwatch_metrics" {
  type        = bool
  description = "The action to perform if none of the rules contained in the WebACL match."
  default     = true
}

variable "is_enable_sampled_requests" {
  type        = bool
  description = "Whether AWS WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the AWS WAF console."
  default     = true
}

variable "ip_rate_based_rule" {
  type = object({
    name     = string
    priority = number
    action   = string
    limit    = number
  })
  description = "A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span"
  default     = null
}

variable "is_create_logging_configuration" {
  description = "Whether to create logging configuration in order start logging from a WAFv2 Web ACL to CloudWatch"
  type        = bool
  default     = true
}

variable "cloudwatch_log_retention_in_days" {
  description = "Specifies the number of days you want to retain log events Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653, and 0. If you select 0, the events in the log group are always retained and never expire"
  type        = number
  default     = 365
}

variable "cloudwatch_log_kms_key_id" {
  description = "The ARN for the KMS encryption key."
  type        = string
  default     = null
}

variable "redacted_fields" {
  description = "The parts of the request that you want to keep out of the logs. Up to 100 `redacted_fields` blocks are supported."
  type        = any
  default     = []
}

variable "logging_filter" {
  description = "A configuration block that specifies which web requests are kept in the logs and which are dropped. You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation."
  type        = any
  default     = {}
}

variable "custom_response_body" {
  description = "(optional) Define custom response body"
  type        = list(any)
  default     = []
}


variable "use_firehose_logs" {
  description = "Set to true to use Kinesis Firehose as the logging destination."
  type        = bool
  default     = false
}

variable "firehose_arn" {
  description = "The ARN of the  Kinesis Firehose delivery stream."
  type        = string
  default     = null
}

variable "use_cloudwatch_logs" {
  description = "Set to true to use CloudWatch Logs as the logging destination."
  type        = bool
  default     = true
}


variable "regex_pattern_set_reference_statement_rules" {
  description = "A list of rules for regex pattern set reference statements"
  type = list(object({
    name     = string
    priority = number
    action   = string
    regex_pattern_set_reference_statement = list(object({
      all_query_arguments   = optional(bool)
      body                  = optional(bool)
      method                = optional(bool)
      query_string          = optional(bool)
      single_header         = optional(string)
      single_query_argument = optional(string)
      uri_path              = optional(bool)
    }))
    text_transformation = list(object({
      priority = number
      type     = string
    }))
    regex_set = list(object({
      regex_string = string
    }))
  }))
  default = []
}
variable "rule_group" {

  default = []
  type    = any
}
