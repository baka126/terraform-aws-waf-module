output "web_acl_id" {
  description = "The ARN of the WAF WebACL."
  value       = module.waf_alb.web_acl_id
}
output "alb_arn" {
  description = "The ARN of the alb."
  value       = module.alb.lb_arn
}

output "rule_group_arn" {
  description = "The ARN of the WAF Rule Group."
  value       = aws_wafv2_rule_group.rule_group.arn
}

output "rule_group_capacity" {
  description = "The capacity of the WAF Rule Group, indicating the computational effort required to process the rules within the group."
  value       = module.waf_alb.rule_group_capacity
}
