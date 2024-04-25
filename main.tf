resource "aws_wafv2_web_acl" "this" {
  depends_on = [
    aws_wafv2_ip_set.ipset,
  ]

  name        = var.name #format("%s-waf", local.name)
  description = "WAFv2 ACL for ${format("%s-waf", var.name)}"
  scope       = var.scope

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }

    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
    sampled_requests_enabled   = var.is_enable_sampled_requests
    metric_name                = "All"
  }

  dynamic "custom_response_body" {
    for_each = var.custom_response_body

    content {
      key          = custom_response_body.value.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
    }
  }
  dynamic "rule" {

    for_each = local.managed_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = lookup(rule.value, "override_action", null) == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = lookup(rule.value, "override_action", null) != "count" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = rule.value.rule_action_override != null ? rule.value.rule_action_override : []

            content {
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action_to_use == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action_to_use == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action_to_use == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action_to_use == "captcha" ? [1] : []
                  content {}
                }

              }

              name = rule_action_override.value.name
            }
          }

          dynamic "excluded_rule" {
            for_each = rule.value.excluded_rules
            content {
              name = excluded_rule.value
            }
          }
        }

      }
      visibility_config {
        cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.is_enable_sampled_requests
      }
    }

  }

  dynamic "rule" {
    for_each = var.custom_rules
    content {

      name     = rule.value.name
      priority = rule.value.priority
      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }

        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", false) == false ? [] : [lookup(rule.value, "custom_response", {})]

              content {
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                response_code            = lookup(custom_response.value, "response_code", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_headers", [])

                  content {
                    name  = response_header.value["name"]
                    value = response_header.value["value"]
                  }
                }
              }
            }
          }
        }
      }

      statement {

        dynamic "and_statement" {
          for_each = rule.value.expression_type == "and-statements" ? [1] : []
          content {
            dynamic "statement" {
              for_each = rule.value.statements
              iterator = user_defined_statement
              content {
                # replace `rule.value.statements[0]` with `user_defined_statement.value`
                # Add `&& lookup(user_defined_statement.value, "is_negated_statement", false) == false` to condition for non not_statement
                /* -------------------------------------------------------------------------- */
                /*      (START): SINGLE MATCH STATEMEN (1) [is_negated_statement = false]     */
                /* -------------------------------------------------------------------------- */
                ## Originates from IP address
                dynamic "ip_set_reference_statement" {
                  for_each = user_defined_statement.value.inspect == local.originate_from_an_ip_addresses_in && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    arn = aws_wafv2_ip_set.this[user_defined_statement.value.ip_set_key].arn
                  }
                }
                ## Originates from country
                #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#country_codes
                dynamic "geo_match_statement" {
                  for_each = user_defined_statement.value.inspect == local.originate_from_a_country_in && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    country_codes = user_defined_statement.value.country_codes
                  }
                }
                ## Labels
                #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#label_match_statement
                dynamic "label_match_statement" {
                  for_each = user_defined_statement.value.inspect == local.has_a_label && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    scope = user_defined_statement.value.scope
                    key   = user_defined_statement.value.key
                  }
                }

                # Request component (byte_match_statement, size_constraint_statement, sqli_match_statement)
                ## byte_match_statement (String Macth Condition)
                #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#byte_match_statement
                dynamic "byte_match_statement" {
                  for_each = contains(local.request_component_dynamic_blocks, user_defined_statement.value.inspect) && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    positional_constraint = user_defined_statement.value.positional_constraint
                    search_string         = user_defined_statement.value.search_string
                    field_to_match {
                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_header
                      dynamic "single_header" {
                        for_each = user_defined_statement.value.inspect == local.single_header && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {
                          name = user_defined_statement.value.header_name
                        }
                      }



                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_query_argument
                      dynamic "single_query_argument" {
                        for_each = user_defined_statement.value.inspect == local.single_query_parameter && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {
                          name = user_defined_statement.value.query_string_name
                        }
                      }

                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#all_query_arguments
                      dynamic "all_query_arguments" {
                        for_each = user_defined_statement.value.inspect == local.all_query_parameters && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }

                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#uri_path
                      dynamic "uri_path" {
                        for_each = user_defined_statement.value.inspect == local.uri_path && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }

                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#query_string
                      dynamic "query_string" {
                        for_each = user_defined_statement.value.inspect == local.query_string && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }



                      dynamic "method" {
                        for_each = user_defined_statement.value.inspect == local.http_method && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }


                    }


                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }

                /* -------------------------------------------------------------------------- */
                /*       (END): SINGLE MATCH STATEMEN (1) [is_negated_statement = false]      */
                /* -------------------------------------------------------------------------- */
                # is_negated_statement = true
                dynamic "not_statement" {
                  for_each = lookup(user_defined_statement.value, "is_negated_statement", false) == true ? [1] : [] # Force false
                  content {
                    statement {
                      # replace `rule.value.statements[0]` with `user_defined_statement.value`
                      /* -------------------------------------------------------------------------- */
                      /*        (START): SINGLE MATCH STATEMEN [is_negated_statement = true]        */
                      /* -------------------------------------------------------------------------- */
                      ## Originates from IP address
                      dynamic "ip_set_reference_statement" {
                        for_each = user_defined_statement.value.inspect == local.originate_from_an_ip_addresses_in ? [1] : []
                        content {
                          arn = aws_wafv2_ip_set.this[user_defined_statement.value.ip_set_key].arn
                        }
                      }
                      ## Originates from country
                      #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#country_codes
                      dynamic "geo_match_statement" {
                        for_each = user_defined_statement.value.inspect == local.originate_from_a_country_in ? [1] : []
                        content {
                          country_codes = user_defined_statement.value.country_codes
                        }
                      }
                      ## Labels
                      #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#label_match_statement
                      dynamic "label_match_statement" {
                        for_each = user_defined_statement.value.inspect == local.has_a_label ? [1] : []
                        content {
                          scope = user_defined_statement.value.scope
                          key   = user_defined_statement.value.key
                        }
                      }

                      # Request component (byte_match_statement, size_constraint_statement, sqli_match_statement)
                      ## byte_match_statement (String Macth Condition)
                      #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#byte_match_statement
                      dynamic "byte_match_statement" {
                        for_each = contains(local.request_component_dynamic_blocks, user_defined_statement.value.inspect) ? [1] : []
                        content {
                          positional_constraint = user_defined_statement.value.positional_constraint
                          search_string         = user_defined_statement.value.search_string
                          field_to_match {
                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_header
                            dynamic "single_header" {
                              for_each = user_defined_statement.value.inspect == local.single_header ? [1] : []
                              content {
                                name = user_defined_statement.value.header_name
                              }
                            }



                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_query_argument
                            dynamic "single_query_argument" {
                              for_each = user_defined_statement.value.inspect == local.single_query_parameter ? [1] : []
                              content {
                                name = user_defined_statement.value.query_string_name
                              }
                            }

                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#all_query_arguments
                            dynamic "all_query_arguments" {
                              for_each = user_defined_statement.value.inspect == local.all_query_parameters ? [1] : []
                              content {

                              }
                            }

                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#uri_path
                            dynamic "uri_path" {
                              for_each = user_defined_statement.value.inspect == local.uri_path ? [1] : []
                              content {

                              }
                            }

                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#query_string
                            dynamic "query_string" {
                              for_each = user_defined_statement.value.inspect == local.query_string ? [1] : []
                              content {

                              }
                            }



                            dynamic "method" {
                              for_each = user_defined_statement.value.inspect == local.http_method ? [1] : []
                              content {

                              }
                            }


                          }

                          #### TODO: support text transformation
                          text_transformation {
                            priority = 0
                            type     = "NONE"
                          }
                        }
                      }

                    }
                  }
                }
              }
            }
          }
        }

        # TODO: support or_statement; can use following dynamic block with some adjustment
        dynamic "or_statement" {
          for_each = rule.value.expression_type == "or-statements" ? [1] : []
          content {
            dynamic "statement" {
              for_each = rule.value.statements
              iterator = user_defined_statement
              content {
                # replace `rule.value.statements[0]` with `user_defined_statement.value`
                # Add `&& lookup(user_defined_statement.value, "is_negated_statement", false) == false` to condition for non not_statement
                /* -------------------------------------------------------------------------- */
                /*      (START): SINGLE MATCH STATEMEN (2) [is_negated_statement = false]     */
                /* -------------------------------------------------------------------------- */
                ## Originates from IP address
                dynamic "ip_set_reference_statement" {
                  for_each = user_defined_statement.value.inspect == local.originate_from_an_ip_addresses_in && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    arn = aws_wafv2_ip_set.this[user_defined_statement.value.ip_set_key].arn
                  }
                }
                ## Originates from country
                #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#country_codes
                dynamic "geo_match_statement" {
                  for_each = user_defined_statement.value.inspect == local.originate_from_a_country_in && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    country_codes = user_defined_statement.value.country_codes
                  }
                }
                ## Labels
                #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#label_match_statement
                dynamic "label_match_statement" {
                  for_each = user_defined_statement.value.inspect == local.has_a_label && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    scope = user_defined_statement.value.scope
                    key   = user_defined_statement.value.key
                  }
                }

                # Request component (byte_match_statement, size_constraint_statement, sqli_match_statement)
                ## byte_match_statement (String Macth Condition)
                #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#byte_match_statement
                dynamic "byte_match_statement" {
                  for_each = contains(local.request_component_dynamic_blocks, user_defined_statement.value.inspect) && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                  content {
                    positional_constraint = user_defined_statement.value.positional_constraint
                    search_string         = user_defined_statement.value.search_string
                    field_to_match {
                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_header
                      dynamic "single_header" {
                        for_each = user_defined_statement.value.inspect == local.single_header && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {
                          name = user_defined_statement.value.header_name
                        }
                      }



                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_query_argument
                      dynamic "single_query_argument" {
                        for_each = user_defined_statement.value.inspect == local.single_query_parameter && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {
                          name = user_defined_statement.value.query_string_name
                        }
                      }

                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#all_query_arguments
                      dynamic "all_query_arguments" {
                        for_each = user_defined_statement.value.inspect == local.all_query_parameters && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }

                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#uri_path
                      dynamic "uri_path" {
                        for_each = user_defined_statement.value.inspect == local.uri_path && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }

                      # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#query_string
                      dynamic "query_string" {
                        for_each = user_defined_statement.value.inspect == local.query_string && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }


                      dynamic "method" {
                        for_each = user_defined_statement.value.inspect == local.http_method && lookup(user_defined_statement.value, "is_negated_statement", false) == false ? [1] : []
                        content {

                        }
                      }


                    }


                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }

                /* -------------------------------------------------------------------------- */
                /*       (END): SINGLE MATCH STATEMEN (2) [is_negated_statement = false]      */
                /* -------------------------------------------------------------------------- */
                # is_negated_statement = true
                dynamic "not_statement" {
                  for_each = lookup(user_defined_statement.value, "is_negated_statement", false) == true ? [1] : [] # Force false
                  content {
                    statement {
                      # replace `rule.value.statements[0]` with `user_defined_statement.value`
                      /* -------------------------------------------------------------------------- */
                      /*      (START): SINGLE MATCH STATEMEN (2) [is_negated_statement = true]      */
                      /* -------------------------------------------------------------------------- */
                      ## Originates from IP address
                      dynamic "ip_set_reference_statement" {
                        for_each = user_defined_statement.value.inspect == local.originate_from_an_ip_addresses_in ? [1] : []
                        content {
                          arn = aws_wafv2_ip_set.this[user_defined_statement.value.ip_set_key].arn
                        }
                      }
                      ## Originates from country
                      #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#country_codes
                      dynamic "geo_match_statement" {
                        for_each = user_defined_statement.value.inspect == local.originate_from_a_country_in ? [1] : []
                        content {
                          country_codes = user_defined_statement.value.country_codes
                        }
                      }
                      ## Labels
                      #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#label_match_statement
                      dynamic "label_match_statement" {
                        for_each = user_defined_statement.value.inspect == local.has_a_label ? [1] : []
                        content {
                          scope = user_defined_statement.value.scope
                          key   = user_defined_statement.value.key
                        }
                      }

                      # Request component (byte_match_statement, size_constraint_statement, sqli_match_statement)
                      ## byte_match_statement (String Macth Condition)
                      #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#byte_match_statement
                      dynamic "byte_match_statement" {
                        for_each = contains(local.request_component_dynamic_blocks, user_defined_statement.value.inspect) ? [1] : []
                        content {
                          positional_constraint = user_defined_statement.value.positional_constraint
                          search_string         = user_defined_statement.value.search_string
                          field_to_match {
                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_header
                            dynamic "single_header" {
                              for_each = user_defined_statement.value.inspect == local.single_header ? [1] : []
                              content {
                                name = user_defined_statement.value.header_name
                              }
                            }



                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_query_argument
                            dynamic "single_query_argument" {
                              for_each = user_defined_statement.value.inspect == local.single_query_parameter ? [1] : []
                              content {
                                name = user_defined_statement.value.query_string_name
                              }
                            }

                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#all_query_arguments
                            dynamic "all_query_arguments" {
                              for_each = user_defined_statement.value.inspect == local.all_query_parameters ? [1] : []
                              content {

                              }
                            }

                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#uri_path
                            dynamic "uri_path" {
                              for_each = user_defined_statement.value.inspect == local.uri_path ? [1] : []
                              content {

                              }
                            }

                            # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#query_string
                            dynamic "query_string" {
                              for_each = user_defined_statement.value.inspect == local.query_string ? [1] : []
                              content {

                              }
                            }



                            dynamic "method" {
                              for_each = user_defined_statement.value.inspect == local.http_method ? [1] : []
                              content {

                              }
                            }


                          }

                          text_transformation {
                            priority = 0
                            type     = "NONE"
                          }
                        }
                      }

                    }
                  }
                }
              }
            }
          }
        }

        dynamic "not_statement" {
          for_each = rule.value.expression_type == "not-statement" ? [1] : []
          content {

          }
        }

        /* -------------------------------------------------------------------------- */
        /*                       (START): SINGLE MATCH STATEMEN                       */
        /* -------------------------------------------------------------------------- */
        ## Originates from IP address
        dynamic "ip_set_reference_statement" {
          for_each = rule.value.expression_type == "match-statement" && rule.value.statements[0].inspect == local.originate_from_an_ip_addresses_in ? [1] : []
          content {
            arn = aws_wafv2_ip_set.this[rule.value.statements[0].ip_set_key].arn
          }
        }
        ## Originates from country
        #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#country_codes
        dynamic "geo_match_statement" {
          for_each = rule.value.expression_type == "match-statement" && rule.value.statements[0].inspect == local.originate_from_a_country_in ? [1] : []
          content {
            country_codes = rule.value.statements[0].country_codes
          }
        }
        ## Labels
        #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#label_match_statement
        dynamic "label_match_statement" {
          for_each = rule.value.expression_type == "match-statement" && rule.value.statements[0].inspect == local.has_a_label ? [1] : []
          content {
            scope = rule.value.statements[0].scope
            key   = rule.value.statements[0].key
          }
        }

        # Request component (byte_match_statement, size_constraint_statement, sqli_match_statement)
        ## byte_match_statement (String Macth Condition)
        #### https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#byte_match_statement
        dynamic "byte_match_statement" {
          for_each = rule.value.expression_type == "match-statement" && contains(local.request_component_dynamic_blocks, rule.value.statements[0].inspect) ? [1] : []
          content {
            positional_constraint = rule.value.statements[0].positional_constraint
            search_string         = rule.value.statements[0].search_string
            field_to_match {
              # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_header
              dynamic "single_header" {
                for_each = rule.value.statements[0].inspect == local.single_header ? [1] : []
                content {
                  name = rule.value.statements[0].header_name
                }
              }


              # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#single_query_argument
              dynamic "single_query_argument" {
                for_each = rule.value.statements[0].inspect == local.single_query_parameter ? [1] : []
                content {
                  name = rule.value.statements[0].query_string_name
                }
              }

              # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#all_query_arguments
              dynamic "all_query_arguments" {
                for_each = rule.value.statements[0].inspect == local.all_query_parameters ? [1] : []
                content {

                }
              }

              # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#uri_path
              dynamic "uri_path" {
                for_each = rule.value.statements[0].inspect == local.uri_path ? [1] : []
                content {

                }
              }

              # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl.html#query_string
              dynamic "query_string" {
                for_each = rule.value.statements[0].inspect == local.query_string ? [1] : []
                content {

                }
              }



              dynamic "method" {
                for_each = rule.value.statements[0].inspect == local.http_method ? [1] : []
                content {

                }
              }

              # Not support for terraform at 2023-06-19
              # dynamic "header_order" {

              # }
            }

            #### TODO: support text transformation
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }

        /* -------------------------------------------------------------------------- */
        /*                        (END): SINGLE MATCH STATEMEN                        */
        /* -------------------------------------------------------------------------- */
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.is_enable_sampled_requests
      }
    }
  }

  # ANCHOR: Can remoove infuture
  dynamic "rule" {
    for_each = var.ip_sets_rule
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }

        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.ipset[index(var.ip_sets_rule, rule.value)].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.is_enable_sampled_requests
      }
    }
  }

  dynamic "rule" {
    for_each = var.ip_rate_based_rule != null ? [var.ip_rate_based_rule] : []
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }

        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = rule.value.limit
          aggregate_key_type = "IP"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.is_enable_sampled_requests
      }
    }
  }
  #############


  dynamic "rule" {
    for_each = try(var.rule_group, {})
    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        rule_group_reference_statement {
          arn = rule.value.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.is_enable_sampled_requests
      }
    }
  }

  ####################
  dynamic "rule" {

    for_each = { for rule in try(var.regex_pattern_set_reference_statement_rules, []) : rule.name => rule }

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []

          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []

          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []

          content {}
        }
      }

      statement {
        regex_pattern_set_reference_statement {
          arn = aws_wafv2_regex_pattern_set.regex_set[rule.value.name].arn

          dynamic "field_to_match" {
            for_each = rule.value.regex_pattern_set_reference_statement

            content {
              dynamic "all_query_arguments" {
                for_each = field_to_match.value.all_query_arguments != null ? [1] : []

                content {}
              }

              dynamic "body" {
                for_each = field_to_match.value.body != null ? [1] : []

                content {}
              }

              dynamic "method" {
                for_each = field_to_match.value.method != null ? [1] : []

                content {}
              }

              dynamic "query_string" {
                for_each = field_to_match.value.query_string != null ? [1] : []

                content {}
              }
              dynamic "single_header" {
                for_each = field_to_match.value.single_header != null ? [1] : []

                content {
                  name = field_to_match.value.single_header
                }
              }
              dynamic "single_query_argument" {
                for_each = field_to_match.value.single_query_argument != null ? [1] : []

                content {
                  name = field_to_match.value.single_query_argument
                }
              }

              dynamic "uri_path" {
                for_each = field_to_match.value.uri_path != null ? [1] : []

                content {}
              }
            }
          }

          dynamic "text_transformation" {
            for_each = { for text_transformation_rule in try(rule.value.text_transformation, []) : text_transformation_rule.priority => text_transformation_rule }

            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }
        }

      }

      visibility_config {
        cloudwatch_metrics_enabled = var.is_enable_cloudwatch_metrics
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.is_enable_sampled_requests
      }

    }
  }


  tags = merge(local.tags, { "Name" = format("%s-waf", var.name) })
}

resource "aws_wafv2_web_acl_association" "this" {
  count = length(var.association_resources)

  resource_arn = var.association_resources[count.index]
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

resource "aws_wafv2_regex_pattern_set" "regex_set" {
  for_each = { for rule in try(var.regex_pattern_set_reference_statement_rules, []) : rule.name => rule }

  name  = "waf-${each.key}"
  scope = var.scope

  dynamic "regular_expression" {
    for_each = each.value.regex_set

    content {
      regex_string = regular_expression.value.regex_string
    }
  }
}
