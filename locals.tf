locals {
  #  name = format("%s-%s-%s", var.prefix, var.environment, var.name) //skipped for terraform naming module
  tags          = var.tags
  default_rules = []
  managed_rules = concat(var.is_enable_default_rule ? local.default_rules : [], var.managed_rules)

  /* ------------------------------ Custom Rules ------------------------------ */
  # unique_dynamic_blocks
  originate_from_a_country_in       = "originate-from-a-country-in"
  originate_from_an_ip_addresses_in = "originate-from-an-ip-addresses-in"
  has_a_label                       = "has-a-label"
  # byte_match_dynamic_blocks
  single_header = "single-header"

  single_query_parameter = "single-query-parameter"
  all_query_parameters   = "all-query-parameters"
  uri_path               = "uri-path"
  query_string           = "query-string"

  http_method = "http-method"

  request_component_dynamic_blocks = [
    local.single_header,
    # local.all_headers,
    # local.cookies,
    local.single_query_parameter,
    local.all_query_parameters,
    local.uri_path,
    local.query_string,
    # local.body,
    # local.json_body,
    local.http_method,
    # local.header_order
  ]
}
