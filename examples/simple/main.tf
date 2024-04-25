
module "waf_cloudfront" {
  source = "../.."

  name  = "cloudfront-waf"
  scope = "CLOUDFRONT" # To work with CloudFront, you must also specify the region us-east-1 (N. Virginia) on the AWS provider.
  ip_sets_rule = [
    {
      name               = "count-ip-set"
      priority           = 5
      action             = "count"
      ip_address_version = "IPV4"
      ip_set             = ["1.2.3.4/32", "5.6.7.8/32"]
    },
    {
      name               = "block-ip-set"
      priority           = 6
      action             = "block"
      ip_address_version = "IPV4"
      ip_set             = ["10.0.1.1/32"]
    }
  ]

  tags = {
    "Custom-Tag" = "1"
  }
}


module "waf_alb" {
  source = "../.."
  name   = "alb-waf"
  scope  = "REGIONAL"

  managed_rules = [
    {
      name                 = "AWSManagedRulesCommonRuleSet",
      priority             = 10
      override_action      = "none"
      excluded_rules       = []
      rule_action_override = []
    }
  ]

  ip_sets_rule = [
    {
      name               = "count-ip-set"
      priority           = 5
      action             = "count"
      ip_address_version = "IPV4"
      ip_set             = ["1.2.3.4/32", "5.6.7.8/32"]
    },
    {
      name               = "block-ip-set"
      priority           = 6
      action             = "block"
      ip_address_version = "IPV4"
      ip_set             = ["10.0.1.1/32"]
    }
  ]

  association_resources = [module.alb.lb_arn]

  tags = {
    "Custom-Tag" = "1"
  }
}
