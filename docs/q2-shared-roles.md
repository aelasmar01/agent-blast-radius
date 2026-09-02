# Q2: How many IAM roles does a real agent deployment use?

Blocking question from the project plan. If agents commonly run every tool under one
shared execution role, per-tool taint propagation degenerates and the tool reduces to
Cloudsplaining with extra YAML. Surveyed 2026-09-01.

## Survey

| Deployment | Tools | Roles behind the tools | Per-tool roles? | Gating available? |
|---|---|---|---|---|
| [awslabs/mcp `iam-mcp-server`](https://github.com/awslabs/mcp/tree/main/src/iam-mcp-server) | 29 `@mcp.tool` | 1 — whatever `AWS_PROFILE` resolves to | **No** | Client-side: per-tool `autoApprove` lists in Cursor / Kiro / VS Code configs (the install links ship `"autoApprove": []`) |
| [awslabs/mcp `dynamodb-mcp-server`](https://github.com/awslabs/mcp/tree/main/src/dynamodb-mcp-server) | 8 | 1 (`AWS_PROFILE`) | **No** | Same, plus a server-wide `DDB-MCP-READONLY` env flag |
| [awslabs/mcp `aws-api-mcp-server`](https://github.com/awslabs/mcp/tree/main/src/aws-api-mcp-server) | effectively 1 (`call_aws`) | 1 (`AWS_API_MCP_PROFILE_NAME`); README says "IAM permissions remain the primary security control" | n/a | `READ_OPERATIONS_ONLY` flag; client `autoApprove` |
| [awslabs/mcp `lambda-tool-mcp-server`](https://github.com/awslabs/mcp/tree/main/src/lambda-tool-mcp-server) | N (one per Lambda) | client holds `lambda:InvokeFunction` only; **each Lambda has its own function role** | **Yes, 1:1** | Client `autoApprove` |
| [Bedrock `cost-explorer-agent`](https://github.com/aws-samples/amazon-bedrock-samples/blob/main/agents-and-function-calling/bedrock-agents/use-case-examples/cost-explorer-agent/agent_template.yaml) | 2 action groups + user-input | 3: `BillingAgentBedrockAgentRole` + `BillingAgentLambdaRole` + `SavingsPlanAgentLambdaRole` | **Yes, per action group**; functions inside one group share | `Function.requireConfirmation: ENABLED \| DISABLED`, per function (verified in the `bedrock-agent` service model) |
| [Bedrock `customer-relationship-management-agent`](https://github.com/aws-samples/amazon-bedrock-samples/blob/main/agents-and-function-calling/bedrock-agents/use-case-examples/customer-relationship-management-agent/codepipeline.yaml) | 1 action group, many functions | 2: `AgentRole` + `AgentLambdaRole` | **No** — every function under `AgentLambdaRole` | Same |
| [Strands `whatsapp-fintech`](https://github.com/strands-agents/samples/blob/main/python/04-industry-use-cases/finance/whatsapp-fintech/template.yaml) | 4 `@tool` | 1 `LambdaExecutionRole` | **No** | None built in |
| [Strands CDK Lambda example](https://github.com/strands-agents/docs/blob/main/site/docs/examples/cdk/deploy_to_lambda/lib/agent-lambda-stack.ts) | 1 | 1 (function role, `bedrock:InvokeModel` added inline) | n/a | None |
| Bedrock AgentCore Gateway ([`CreateGateway` / `CreateGatewayTarget`](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html)) | N targets | one gateway `roleArn` invokes every Lambda target (`credentialProviderType: GATEWAY_IAM_ROLE`); each Lambda still has its own execution role | **Partially** — per-target Lambda roles behind a shared invoker | `policyEngineConfiguration`, `interceptorConfigurations` on the gateway |

## Findings

1. **Shared credentials are the default for locally-run MCP servers and for
   framework-on-Lambda deployments.** 29 tools under one profile is normal. The
   `aws-api-mcp-server` README says it outright: IAM permissions on the single
   credential are the security control.
2. **Per-tool roles exist wherever tools are Lambda-backed**: Bedrock action groups,
   `lambda-tool-mcp-server`, AgentCore Gateway Lambda targets. That is also the only
   architecture where the flagship `iam:PassRole` + `lambda:CreateFunction` chain is
   a natural fit, because the agent side is already minting Lambdas.
3. **Gating is present, per tool, in every platform surveyed**: MCP client
   `autoApprove`, Bedrock `requireConfirmation`, AgentCore policy engine. It is the one
   dimension a deployment always has, whether or not it has distinct roles.

## Decision

**Outcome: mixed — so gating becomes the load-bearing axis, and the role graph stays
as the map.**

- The fixture keeps per-tool roles, because that is the honest shape of a Bedrock
  agent with Lambda-backed action groups, and it is where the PassRole chain is real.
- The fixture is restructured so the finding **cannot** be reproduced by resolving one
  role's policy: two tools share `agent-execution-role`, one gated and one not, and the
  direct path to `iam:*` (`rotate_credentials`) is gated. The chain exists only through
  the ungated tool. A report that just prints "the shared role's capability set" gets
  the wrong answer on this fixture, which is the point.
- For shared-credential deployments (the awslabs/mcp case) the analyzer's output is
  still meaningful **only** because of gating: the reachable set is the credential's
  capability set minus what sits behind approval. Without gating annotations on a
  single-role deployment, the tool must say so rather than print Cloudsplaining output
  with a different logo. Enforced in the report: a deployment with one role and no
  gated tools gets an explicit "taint propagation adds nothing here" notice.
- The headline sentence stays. Four ungated tools still look scoped, and the chain is
  still three hops.
