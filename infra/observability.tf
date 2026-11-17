# Alarms to one SNS topic. Subscribe by email with var.alarm_email (AWS sends
# a confirmation email first).

resource "aws_sns_topic" "alarms" {
  name = "${local.name}-alarms"
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count     = var.alarm_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alb_dimensions = { LoadBalancer = aws_lb.main.arn_suffix }
  tg_dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.proxy.arn_suffix
  }
  db_dimensions = { DBInstanceIdentifier = aws_db_instance.main.identifier }

  alarms = {
    alb-5xx = {
      description = "The load balancer itself returned 5xx (no healthy proxy, or timeouts)"
      namespace   = "AWS/ApplicationELB", metric = "HTTPCode_ELB_5XX_Count", statistic = "Sum"
      dimensions  = local.alb_dimensions, threshold = 5, comparison = "GreaterThanOrEqualToThreshold"
      periods     = 1
    }
    proxy-5xx = {
      description = "The proxy returned 5xx; 503s include refusals while the session store is down"
      namespace   = "AWS/ApplicationELB", metric = "HTTPCode_Target_5XX_Count", statistic = "Sum"
      dimensions  = local.tg_dimensions, threshold = 10, comparison = "GreaterThanOrEqualToThreshold"
      periods     = 1
    }
    no-healthy-proxy = {
      description = "No proxy task is passing health checks"
      namespace   = "AWS/ApplicationELB", metric = "HealthyHostCount", statistic = "Minimum"
      dimensions  = local.tg_dimensions, threshold = 1, comparison = "LessThanThreshold"
      periods     = 3
    }
    db-cpu = {
      description = "Database CPU above 80%"
      namespace   = "AWS/RDS", metric = "CPUUtilization", statistic = "Average"
      dimensions  = local.db_dimensions, threshold = 80, comparison = "GreaterThanThreshold"
      periods     = 3
    }
    db-storage = {
      description = "Database free storage below 2 GiB"
      namespace   = "AWS/RDS", metric = "FreeStorageSpace", statistic = "Minimum"
      dimensions  = local.db_dimensions, threshold = 2147483648, comparison = "LessThanThreshold"
      periods     = 1
    }
  }

  # Decision records are JSON lines in the proxy's log (ROUTER_LOG_PATH=-).
  decision_alarms = {
    session-store-unavailable = {
      description = "Requests refused because the session store was unreachable (fails closed)"
      pattern     = "{ $.matched_rules[0] = \"session_store_unavailable\" }"
    }
    session-tampered = {
      description = "A stored session failed its integrity check: someone changed the database"
      pattern     = "{ $.matched_rules[0] = \"session_tampered\" }"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "infra" {
  for_each            = local.alarms
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = each.value.statistic
  dimensions          = each.value.dimensions
  period              = 300
  evaluation_periods  = each.value.periods
  threshold           = each.value.threshold
  comparison_operator = each.value.comparison
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_log_metric_filter" "decisions" {
  for_each       = local.decision_alarms
  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.proxy.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = "SecureLiteLLM/${local.name}"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "decisions" {
  for_each            = local.decision_alarms
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "SecureLiteLLM/${local.name}"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.decisions]
}
