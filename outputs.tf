output "web_acl_id" {
  description = "The ARN of the WAF WebACL."
  value       = aws_wafv2_web_acl.this.id
}
output "rule_group_arn" {
  description = "The ARN of the WAF Rule Group."
  value       = aws_wafv2_web_acl.this.arn
}

output "rule_group_capacity" {
  description = "The capacity of the WAF Rule Group, indicating the computational effort required to process the rules within the group."
  value       = aws_wafv2_web_acl.this.capacity
}
