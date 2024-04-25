
module "waf_alb" {
  source = "../.."
  name   = "test-waf"

  scope = "REGIONAL"

  ###Place the aws managed rules inside managed_rules block##
  ### 1 managed group only supports excluded_rules or rule_action_override only one at a time##
  ## sub-rules url https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html ##
  managed_rules = [
    {
      name            = "AWSManagedRulesCommonRuleSet",
      priority        = 10
      override_action = "count"
      excluded_rules  = []
      rule_action_override = [
        {
          name          = "UserAgent_BadBots_HEADER"
          action_to_use = "allow"
        }
      ]
    },
    {
      name                 = "AWSManagedRulesKnownBadInputsRuleSet",
      priority             = 30
      override_action      = "none"
      excluded_rules       = ["JavaDeserializationRCE_HEADER", "JavaDeserializationRCE_BODY"]
      rule_action_override = []
    }

  ]

  custom_rules = [
    {
      name            = "allow-access-to-public-path" #
      priority        = 70                            ##
      action          = "allow"                       # {count, allow, block}
      expression_type = "or-statements"               ##
      statements = [                                  ##
        {
          inspect               = "uri-path"
          positional_constraint = "STARTS_WITH"
          search_string         = "/uploads"
        },
        {
          inspect               = "uri-path"
          positional_constraint = "STARTS_WITH"
          search_string         = "/images"
        },
      ]
    },
    {
      name            = "allow-access-from-vpn" #
      priority        = 80                      ##
      action          = "allow"                 # {count, allow, block}
      expression_type = "or-statements"         ##
      statements = [                            ##
        {
          inspect              = "originate-from-an-ip-addresses-in"
          is_negated_statement = true
          ip_set_key           = "allow-ipv4-set"
        },
        {
          inspect              = "originate-from-an-ip-addresses-in"
          is_negated_statement = true
          ip_set_key           = "allow-ipv6-set"
        },
      ]
    }
  ]

  regex_pattern_set_reference_statement_rules = [
    {
      name     = "ExampleRegexRule1"
      priority = 100
      action   = "block"
      regex_pattern_set_reference_statement = [
        {
          uri_path = true
        }
      ]
      text_transformation = [
        {
          priority = 0
          type     = "NONE"
        }
      ]
      regex_set = [
        {
          regex_string = "^/admin.*"
        }
      ]
    }
  ]
  custom_response_body = [
    {
      key          = "custom-response"
      content      = <<EOL
      {
        "data": {
            "code": "OUT_OF_THAILAND"
        }
      }
      EOL
      content_type = "APPLICATION_JSON"
    }
  ]

  rule_group = [
    {
      name            = "CountDNS"
      priority        = 300
      override_action = "none"
      arn             = aws_wafv2_rule_group.rule_group.arn

    }
  ]

  ip_set = {
    "allow-ipv4-set" = {
      ip_addresses       = ["127.0.0.1/32", "127.0.0.2/32", "127.0.0.3/32", "127.0.0.4/32", "127.0.0.5/32"]
      ip_address_version = "IPV4"
    },
    "allow-ipv6-set" = {
      ip_addresses       = ["1234:5678:9101:1121:3141:5161:7181:9202/128"],
      ip_address_version = "IPV6"
    }
  }

  association_resources = [module.alb.lb_arn]

  tags = var.custom_tags
}
