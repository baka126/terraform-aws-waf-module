# AWS WAF Terraform Module



## Custom Rules Usage

```terraform
waf_custom_rules = [
  {
    name            = "match-originate-from-an-ip-addresses-in-rule" #
    priority        = 10                                             ##
    action          = "count"                                        # {count, allow, block}
    expression_type = "match-statement"                              ##
    statements = [                                                   ##
      {
        inspect    = "originate-from-an-ip-addresses-in" ##
        ip_set_key = "baka-vpn-ipv4-set"                # Match above
      }
    ]
  },
  {
    name            = "match-originate-from-a-country-in-rule" #
    priority        = 20                                       ##
    action          = "count"                                  # {count, allow, block}
    expression_type = "match-statement"                        ##
    statements = [                                             ##
      {
        inspect       = "originate-from-a-country-in" ##
        country_codes = ["NP"]
      }
    ]
  },
  {
    name            = "match-has-a-label-rule" #
    priority        = 30                       ##
    action          = "count"                  # {count, allow, block}
    expression_type = "match-statement"        ##
    statements = [                             ##
      {
        inspect = "has-a-label" ##
        scope   = "LABEL"
        key     = "awswaf:managed:aws:core-rule-set:GenericLFI_URIPath"
      }
    ]
  },
  /* -------------------------------------------------------------------------- */
  /*                       Strgin Match Condition Example                       */
  /* -------------------------------------------------------------------------- */
  {
    name            = "match-request-component-single-header-rule" #
    priority        = 40                                           ##
    action          = "count"                                      # {count, allow, block}
    expression_type = "match-statement"                            ##
    statements = [                                                 ##
      {
        inspect               = "single-header" ##
        header_name           = "host"
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    ## Not available (just for test case)
    name            = "match-request-component-all-headers-rule" #
    priority        = 41                                         ##
    action          = "count"                                    # {count, allow, block}
    expression_type = "match-statement"                          ##
    statements = [                                               ##
      {
        inspect               = "all-headers" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    ## Not available (just for test case)
    name            = "match-request-component-cookies-rule" #
    priority        = 42                                     ##
    action          = "count"                                # {count, allow, block}
    expression_type = "match-statement"                      ##
    statements = [                                           ##
      {
        inspect               = "cookies" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    name            = "match-request-component-single-query-parameter-rule" #
    priority        = 43                                                    ##
    action          = "count"                                               # {count, allow, block}
    expression_type = "match-statement"                                     ##
    statements = [                                                          ##
      {
        inspect               = "single-query-parameter" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
        query_string_name     = "user"
      }
    ]
  },
  {
    name            = "match-request-component-all-query-parameters-rule" #
    priority        = 44                                                  ##
    action          = "count"                                             # {count, allow, block}
    expression_type = "match-statement"                                   ##
    statements = [                                                        ##
      {
        inspect               = "all-query-parameters" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    name            = "match-request-component-uri-path-rule" #
    priority        = 45                                      ##
    action          = "count"                                 # {count, allow, block}
    expression_type = "match-statement"                       ##
    statements = [                                            ##
      {
        inspect               = "uri-path" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    name            = "match-request-component-query-string-rule" #
    priority        = 46                                          ##
    action          = "count"                                     # {count, allow, block}
    expression_type = "match-statement"                           ##
    statements = [                                                ##
      {
        inspect               = "query-string" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  ## Not available (just for test case)
  {
    name            = "match-request-component-body-rule" #
    priority        = 47                                  ##
    action          = "count"                             # {count, allow, block}
    expression_type = "match-statement"                   ##
    statements = [                                        ##
      {
        inspect               = "body" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    ## Not available (just for test case)
    name            = "match-request-component-json-body-rule" #
    priority        = 48                                       ##
    action          = "count"                                  # {count, allow, block}
    expression_type = "match-statement"                        ##
    statements = [                                             ##
      {
        inspect               = "json-body" ##
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      }
    ]
  },
  {
    name            = "match-request-component-http-method-rule" #
    priority        = 49                                         ##
    action          = "count"                                    # {count, allow, block}
    expression_type = "match-statement"                          ##
    statements = [                                               ##
      {
        inspect               = "http-method" ##
        positional_constraint = "CONTAINS"
        search_string         = "post"
      }
    ]
  },
  /* -------------------------------------------------------------------------- */
  /*                                And Statement                               */
  /* -------------------------------------------------------------------------- */
  {
    name            = "match-request-component-http-method-rule" #
    priority        = 50                                         ##
    action          = "count"                                    # {count, allow, block}
    expression_type = "and-statements"                           ##
    statements = [                                               ##
      {
        inspect               = "http-method" ##
        is_negated_statement  = false
        positional_constraint = "CONTAINS"
        search_string         = "post"
      },
      {
        inspect               = "single-header" ##
        header_name           = "host"
        is_negated_statement  = true
        positional_constraint = "CONTAINS"
        search_string         = "STRING_TO_SEARCH"
      },
      {
        inspect    = "originate-from-an-ip-addresses-in" ##
        ip_set_key = "oozou-vpn-ipv4-set"
      },
      {
        inspect       = "originate-from-a-country-in" ##
        country_codes = ["TH"]
      }
    ]
  },
]
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 4.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 4.67.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_wafv2_ip_set.ipset](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_regex_pattern_set.regex_set](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_regex_pattern_set) | resource |
| [aws_wafv2_web_acl.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [aws_wafv2_web_acl_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |
| [aws_wafv2_web_acl_logging_configuration.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_association_resources"></a> [association\_resources](#input\_association\_resources) | ARN of the ALB, CloudFront, Etc to be associated with the WAFv2 ACL. | `list(string)` | `[]` | no |
| <a name="input_cloudwatch_log_kms_key_id"></a> [cloudwatch\_log\_kms\_key\_id](#input\_cloudwatch\_log\_kms\_key\_id) | The ARN for the KMS encryption key. | `string` | `null` | no |
| <a name="input_cloudwatch_log_retention_in_days"></a> [cloudwatch\_log\_retention\_in\_days](#input\_cloudwatch\_log\_retention\_in\_days) | Specifies the number of days you want to retain log events Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653, and 0. If you select 0, the events in the log group are always retained and never expire | `number` | `365` | no |
| <a name="input_custom_response_body"></a> [custom\_response\_body](#input\_custom\_response\_body) | (optional) Define custom response body | `list(any)` | `[]` | no |
| <a name="input_custom_rules"></a> [custom\_rules](#input\_custom\_rules) | Find the example for these structure | `any` | `[]` | no |
| <a name="input_default_action"></a> [default\_action](#input\_default\_action) | The action to perform if none of the rules contained in the WebACL match. | `string` | `"block"` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | Environment Variable used as a prefix | `string` | n/a | yes |
| <a name="input_firehose_arn"></a> [firehose\_arn](#input\_firehose\_arn) | The ARN of the  Kinesis Firehose delivery stream. | `string` | `null` | no |
| <a name="input_ip_rate_based_rule"></a> [ip\_rate\_based\_rule](#input\_ip\_rate\_based\_rule) | A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span | <pre>object({<br>    name     = string<br>    priority = number<br>    action   = string<br>    limit    = number<br>  })</pre> | `null` | no |
| <a name="input_ip_set"></a> [ip\_set](#input\_ip\_set) | To create IP set ex.<br>  ip\_sets = {<br>    "adex-vpn-ipv4-set" = {<br>      ip\_addresses       = ["127.0.01/32"]<br>      ip\_address\_version = "IPV4"<br>    },<br>    "adex-vpn-ipv6-set" = {<br>      ip\_addresses       = ["2403:6200:88a2:a6f8:2096:9b42:31f8:61fd/128"]<br>      ip\_address\_version = "IPV6"<br>    }<br>  } | <pre>map(object({<br>    ip_addresses       = list(string)<br>    ip_address_version = string<br>  }))</pre> | `{}` | no |
| <a name="input_ip_sets_rule"></a> [ip\_sets\_rule](#input\_ip\_sets\_rule) | A rule to detect web requests coming from particular IP addresses or address ranges. | <pre>list(object({<br>    name               = string<br>    priority           = number<br>    ip_set             = list(string)<br>    action             = string<br>    ip_address_version = string<br>  }))</pre> | `[]` | no |
| <a name="input_is_create_logging_configuration"></a> [is\_create\_logging\_configuration](#input\_is\_create\_logging\_configuration) | Whether to create logging configuration in order start logging from a WAFv2 Web ACL to CloudWatch | `bool` | `true` | no |
| <a name="input_is_enable_cloudwatch_metrics"></a> [is\_enable\_cloudwatch\_metrics](#input\_is\_enable\_cloudwatch\_metrics) | The action to perform if none of the rules contained in the WebACL match. | `bool` | `true` | no |
| <a name="input_is_enable_default_rule"></a> [is\_enable\_default\_rule](#input\_is\_enable\_default\_rule) | If true with enable default rule (detail in locals.tf) | `bool` | `true` | no |
| <a name="input_is_enable_sampled_requests"></a> [is\_enable\_sampled\_requests](#input\_is\_enable\_sampled\_requests) | Whether AWS WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the AWS WAF console. | `bool` | `true` | no |
| <a name="input_logging_filter"></a> [logging\_filter](#input\_logging\_filter) | A configuration block that specifies which web requests are kept in the logs and which are dropped. You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation. | `any` | `{}` | no |
| <a name="input_managed_rules"></a> [managed\_rules](#input\_managed\_rules) | List of Managed WAF rules. | <pre>list(object({<br>    name            = string<br>    priority        = number<br>    override_action = string<br>    excluded_rules  = list(string)<br>    rule_action_override = list(object({<br>      name          = string<br>      action_to_use = string<br>    }))<br>  }))</pre> | `[]` | no |
| <a name="input_name"></a> [name](#input\_name) | A friendly name of the WebACL. | `string` | n/a | yes |
| <a name="input_redacted_fields"></a> [redacted\_fields](#input\_redacted\_fields) | The parts of the request that you want to keep out of the logs. Up to 100 `redacted_fields` blocks are supported. | `any` | `[]` | no |
| <a name="input_regex_pattern_set_reference_statement_rules"></a> [regex\_pattern\_set\_reference\_statement\_rules](#input\_regex\_pattern\_set\_reference\_statement\_rules) | A list of rules for regex pattern set reference statements | <pre>list(object({<br>    name     = string<br>    priority = number<br>    action   = string<br>    regex_pattern_set_reference_statement = list(object({<br>      all_query_arguments   = optional(bool)<br>      body                  = optional(bool)<br>      method                = optional(bool)<br>      query_string          = optional(bool)<br>      single_header         = optional(string)<br>      single_query_argument = optional(string)<br>      uri_path              = optional(bool)<br>    }))<br>    text_transformation = list(object({<br>      priority = number<br>      type     = string<br>    }))<br>    regex_set = list(object({<br>      regex_string = string<br>    }))<br>  }))</pre> | `[]` | no |
| <a name="input_rule_group"></a> [rule\_group](#input\_rule\_group) | n/a | `any` | `[]` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Specifies whether this is for an AWS CloudFront distribution or for a regional application.<br>Possible values are `CLOUDFRONT` or `REGIONAL`.<br>To work with CloudFront, you must also specify the region us-east-1 (N. Virginia) on the AWS provider. | `string` | n/a | yes |
| <a name="input_tags"></a> [tags](#input\_tags) | A mapping of tags to assign to the WAFv2 ACL. | `map(string)` | `{}` | no |
| <a name="input_use_cloudwatch_logs"></a> [use\_cloudwatch\_logs](#input\_use\_cloudwatch\_logs) | Set to true to use CloudWatch Logs as the logging destination. | `bool` | `true` | no |
| <a name="input_use_firehose_logs"></a> [use\_firehose\_logs](#input\_use\_firehose\_logs) | Set to true to use Kinesis Firehose as the logging destination. | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_rule_group_arn"></a> [rule\_group\_arn](#output\_rule\_group\_arn) | The ARN of the WAF Rule Group. |
| <a name="output_rule_group_capacity"></a> [rule\_group\_capacity](#output\_rule\_group\_capacity) | The capacity of the WAF Rule Group, indicating the computational effort required to process the rules within the group. |
| <a name="output_web_acl_id"></a> [web\_acl\_id](#output\_web\_acl\_id) | The ARN of the WAF WebACL. |
<!-- END_TF_DOCS -->
