resource "aws_wafv2_ip_set" "ipset" {
  count              = length(var.ip_sets_rule)
  name               = var.ip_sets_rule[count.index].name
  scope              = var.scope
  ip_address_version = var.ip_sets_rule[count.index].ip_address_version
  addresses          = var.ip_sets_rule[count.index].ip_set
}

resource "aws_wafv2_ip_set" "this" {
  for_each = var.ip_set

  name               = each.key
  scope              = var.scope
  addresses          = each.value.ip_addresses
  ip_address_version = each.value.ip_address_version
}
