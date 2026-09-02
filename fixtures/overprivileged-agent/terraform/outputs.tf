output "tool_roles" {
  description = "Tool name -> execution role ARN, for eyeballing the fixture."
  value = {
    read_support_ticket   = aws_iam_role.ticket_reader.arn
    query_customer_record = aws_iam_role.customer_lookup.arn
    call_internal_api     = aws_iam_role.internal_api.arn
    deploy_helper         = aws_iam_role.agent_execution.arn
    run_maintenance_job   = aws_iam_role.agent_execution.arn
    rotate_credentials    = aws_iam_role.incident_response.arn
  }
}
