> **Amazon Confidential**

# Amazon Bedrock (AgentCore Control) — Mitigation Report

---

This report lists all mitigations from the Amazon Bedrock AgentCore Control threat model. Each mitigation represents a security-relevant statement about how an entity should be configured or operated, mapped to the mitigation goal it supports and the request parameters it covers.

---

## Summary

| Entity | Mitigations |
|--------|----------------|
| AgentRuntime | 16 |
| Gateway | 13 |
| Memory | 8 |
| **Total** | **37** |

---

## AgentRuntime

### M-AgentRuntime.0 — An Amazon Bedrock AgentCore Agent Runtime's IAM execution role should only be assumable by the Amazon Bedrock AgentCore principal on behalf of a trusted resource, AWS Account or AWS Organization

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.0 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime's IAM execution role should only be assumable by the Amazon Bedrock AgentCore principal on behalf of a trusted resource, AWS Account or AWS Organization |
| **Mitigation Goal** | Confused Deputy Prevention - Service Roles |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.roleArn`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.roleArn`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.1 — An Amazon Bedrock AgentCore Agent Runtime should use authentication integrated with AWS IAM for authorization

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.1 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should use authentication integrated with AWS IAM for authorization |
| **Mitigation Goal** | IAM Integration for Service Authentication |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.2 — An Amazon Bedrock AgentCore Agent Runtime should be accessed only by trusted identities or AWS services

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.2 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be accessed only by trusted identities or AWS services |
| **Mitigation Goal** | Identity Perimeter - Trusted Identities |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/DeleteResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.3 — An Amazon Bedrock AgentCore Agent Runtime should be restricted to accessing resources only from approved networks

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.3 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be restricted to accessing resources only from approved networks |
| **Mitigation Goal** | Network Perimeter - Approved Networks |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.securityGroups[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.securityGroups[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.4 — An Amazon Bedrock AgentCore Agent Runtime should be placed in only private subnets

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.4 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be placed in only private subnets |
| **Mitigation Goal** | Private Subnet Placement |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.5 — An Amazon Bedrock AgentCore Agent Runtime should be restricted to accessing only trusted resources

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.5 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be restricted to accessing only trusted resources |
| **Mitigation Goal** | Resource Perimeter - Trusted Resources |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.roleArn`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.roleArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.6 — An Amazon Bedrock AgentCore Agent Runtime resource policy should limit permissions to a subset of IAM principals, rather than granting access to all IAM principals.

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.6 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime resource policy should limit permissions to a subset of IAM principals, rather than granting access to all IAM principals. |
| **Mitigation Goal** | Resource Policy - Enforce Explicit Principal Definition |
| **Request Parameters** | `bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/DeleteResourcePolicy/$.resourceArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.7 — An Amazon Bedrock AgentCore Agent Runtime should not be tagged with personally identifiable information (PII) or other confidential or sensitive information

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.7 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should not be tagged with personally identifiable information (PII) or other confidential or sensitive information |
| **Mitigation Goal** | Resource Tagging - No PII |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.resourceArn`<br>`bedrock-agentcore-control/TagResource/$.tags{key}`<br>`bedrock-agentcore-control/ListTagsForResource/$.resourceArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.8 — An Amazon Bedrock AgentCore Agent Runtime should be tagged with information that describes the owner and purpose

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.8 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be tagged with information that describes the owner and purpose |
| **Mitigation Goal** | Resource Tagging - Owner and Purpose |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.resourceArn`<br>`bedrock-agentcore-control/TagResource/$.tags{key}`<br>`bedrock-agentcore-control/UntagResource/$.resourceArn`<br>`bedrock-agentcore-control/UntagResource/$.tagKeys[*]`<br>`bedrock-agentcore-control/ListTagsForResource/$.resourceArn`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.9 — An Amazon Bedrock AgentCore Agent Runtime IAM service role should be accessed only by trusted identities or AWS services acting on behalf of trusted identities

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.9 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime IAM service role should be accessed only by trusted identities or AWS services acting on behalf of trusted identities |
| **Mitigation Goal** | Restrict IAM Role Assumption - Service Roles |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.roleArn`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.roleArn`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.10 — An Amazon Bedrock AgentCore Agent Runtime that uses Custom JWT Authorizer to authenticate principals should be configured with only trusted JWT configuration identifiers

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.10 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime that uses Custom JWT Authorizer to authenticate principals should be configured with only trusted JWT configuration identifiers |
| **Mitigation Goal** | Trusted SSO Configuration |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.11 — An Amazon Bedrock AgentCore Agent Runtime should not allow unauthenticated access

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.11 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should not allow unauthenticated access |
| **Mitigation Goal** | Unauthenticated Access Prevention |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.agentRuntimeId`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.12 — An Amazon Bedrock AgentCore Agent Runtime should be in an Amazon VPC

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.12 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be in an Amazon VPC |
| **Mitigation Goal** | VPC Deployment |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.securityGroups[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.securityGroups[*]`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.13 — An Amazon Bedrock AgentCore Agent Runtime should be configured with a resource policy that requires all connections to be encrypted in transit

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.13 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be configured with a resource policy that requires all connections to be encrypted in transit |
| **Mitigation Goal** | Encryption in Transit - Resource Policy |
| **Request Parameters** | `bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/DeleteResourcePolicy/$.resourceArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.14 — An Amazon Bedrock AgentCore Agent Runtime should have an Elastic Network Interface (ENI) in more than one availability zone (AZ)

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.14 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should have an Elastic Network Interface (ENI) in more than one availability zone (AZ) |
| **Mitigation Goal** | Multi-AZ ENI Deployment |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

### M-AgentRuntime.15 — An Amazon Bedrock AgentCore Agent Runtime should be accessed only from approved networks

| Attribute | Detail |
|-----------|--------|
| **ID** | M-AgentRuntime.15 |
| **Statement** | An Amazon Bedrock AgentCore Agent Runtime should be accessed only from approved networks |
| **Mitigation Goal** | Network Perimeter - Resource Access |
| **Request Parameters** | `bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.securityGroups[*]`<br>`bedrock-agentcore-control/CreateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkMode`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.securityGroups[*]`<br>`bedrock-agentcore-control/UpdateAgentRuntime/$.networkConfiguration.networkModeConfig.subnets[*]`<br>`bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/DeleteResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetAgentRuntime/$.agentRuntimeId` |
| **Resource Type** | `AWS::BedrockAgentCore::Runtime` |

---

## Gateway

### M-Gateway.0 — An Amazon Bedrock AgentCore Gateway should have CloudWatch logging enabled

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.0 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should have CloudWatch logging enabled |
| **Mitigation Goal** | CloudWatch Logging |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.exceptionLevel`<br>`bedrock-agentcore-control/UpdateGateway/$.exceptionLevel`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.1 — An Amazon Bedrock AgentCore Gateway's IAM service role should only be assumable by the Amazon Bedrock AgentCore principal on behalf of a trusted resource, AWS Account or AWS Organization

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.1 |
| **Statement** | An Amazon Bedrock AgentCore Gateway's IAM service role should only be assumable by the Amazon Bedrock AgentCore principal on behalf of a trusted resource, AWS Account or AWS Organization |
| **Mitigation Goal** | Confused Deputy Prevention - Service Roles |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.roleArn`<br>`bedrock-agentcore-control/UpdateGateway/$.roleArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.2 — An Amazon Bedrock AgentCore Gateway should use authorizer configuration integrated with AWS IAM for authentication

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.2 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should use authorizer configuration integrated with AWS IAM for authentication |
| **Mitigation Goal** | IAM Integration for Service Authentication |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.authorizerType`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerType`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.gatewayIdentifier`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.3 — An Amazon Bedrock AgentCore Gateway should be accessed only by trusted identities or AWS services

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.3 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should be accessed only by trusted identities or AWS services |
| **Mitigation Goal** | Identity Perimeter - Trusted Identities |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.authorizerType`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerType`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.gatewayIdentifier`<br>`bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/DeleteResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.4 — An Amazon Bedrock AgentCore Gateway should be encrypted with an AWS KMS Customer Managed Key (CMK)

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.4 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should be encrypted with an AWS KMS Customer Managed Key (CMK) |
| **Mitigation Goal** | KMS Customer Managed Key (CMK) Encryption |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.kmsKeyArn`<br>`bedrock-agentcore-control/UpdateGateway/$.kmsKeyArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.5 — An Amazon Bedrock AgentCore Gateway should be restricted to accessing resources only from approved networks

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.5 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should be restricted to accessing resources only from approved networks |
| **Mitigation Goal** | Network Perimeter - Approved Networks |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.roleArn`<br>`bedrock-agentcore-control/UpdateGateway/$.roleArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.6 — An Amazon Bedrock AgentCore Gateway should be restricted to accessing only trusted resources

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.6 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should be restricted to accessing only trusted resources |
| **Mitigation Goal** | Resource Perimeter - Trusted Resources |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.roleArn`<br>`bedrock-agentcore-control/UpdateGateway/$.roleArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.7 — An Amazon Bedrock AgentCore Gateway resource policy should limit permissions to a subset of IAM principals, rather than granting access to all IAM principals.

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.7 |
| **Statement** | An Amazon Bedrock AgentCore Gateway resource policy should limit permissions to a subset of IAM principals, rather than granting access to all IAM principals. |
| **Mitigation Goal** | Resource Policy - Enforce Explicit Principal Definition |
| **Request Parameters** | `bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/DeleteResourcePolicy/$.resourceArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.8 — An Amazon Bedrock AgentCore Gateway should not be tagged with personally identifiable information (PII) or other confidential or sensitive information

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.8 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should not be tagged with personally identifiable information (PII) or other confidential or sensitive information |
| **Mitigation Goal** | Resource Tagging - No PII |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.resourceArn`<br>`bedrock-agentcore-control/TagResource/$.tags{key}`<br>`bedrock-agentcore-control/ListTagsForResource/$.resourceArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.9 — An Amazon Bedrock AgentCore Gateway should be tagged with information that describes the owner and purpose

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.9 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should be tagged with information that describes the owner and purpose |
| **Mitigation Goal** | Resource Tagging - Owner and Purpose |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.resourceArn`<br>`bedrock-agentcore-control/TagResource/$.tags{key}`<br>`bedrock-agentcore-control/UntagResource/$.resourceArn`<br>`bedrock-agentcore-control/UntagResource/$.tagKeys[*]`<br>`bedrock-agentcore-control/ListTagsForResource/$.resourceArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.10 — An Amazon Bedrock AgentCore Gateway IAM service role should be accessed only by trusted identities or AWS services acting on behalf of trusted identities

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.10 |
| **Statement** | An Amazon Bedrock AgentCore Gateway IAM service role should be accessed only by trusted identities or AWS services acting on behalf of trusted identities |
| **Mitigation Goal** | Restrict IAM Role Assumption - Service Roles |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.roleArn`<br>`bedrock-agentcore-control/UpdateGateway/$.roleArn`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.11 — An Amazon Bedrock AgentCore Gateway that uses Custom JWT authorization to authenticate principals should be configured with only trusted JWT issuer discovery URLs, allowed audiences, allowed clients, and allowed scopes

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.11 |
| **Statement** | An Amazon Bedrock AgentCore Gateway that uses Custom JWT authorization to authenticate principals should be configured with only trusted JWT issuer discovery URLs, allowed audiences, allowed clients, and allowed scopes |
| **Mitigation Goal** | Trusted SSO Configuration |
| **Request Parameters** | `bedrock-agentcore-control/CreateGateway/$.authorizerType`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/CreateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerType`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.discoveryUrl`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedAudience[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedClients[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.allowedScopes[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimName`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].inboundTokenClaimValueType`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchOperator`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueString`<br>`bedrock-agentcore-control/UpdateGateway/$.authorizerConfiguration.customJWTAuthorizer.customClaims[*].authorizingClaimMatchValue.claimMatchValue.matchValueStringList[*]`<br>`bedrock-agentcore-control/UpdateGateway/$.gatewayIdentifier`<br>`bedrock-agentcore-control/GetGateway/$.gatewayIdentifier` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

### M-Gateway.12 — An Amazon Bedrock AgentCore Gateway should not allow unauthenticated access

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Gateway.12 |
| **Statement** | An Amazon Bedrock AgentCore Gateway should not allow unauthenticated access |
| **Mitigation Goal** | Unauthenticated Access Prevention |
| **Request Parameters** | `bedrock-agentcore-control/PutResourcePolicy/$.policy`<br>`bedrock-agentcore-control/PutResourcePolicy/$.resourceArn`<br>`bedrock-agentcore-control/GetResourcePolicy/$.resourceArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Gateway` |

---

## Memory

### M-Memory.0 — An Amazon Bedrock AgentCore Memory should have CloudWatch logging enabled

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.0 |
| **Statement** | An Amazon Bedrock AgentCore Memory should have CloudWatch logging enabled |
| **Mitigation Goal** | CloudWatch Logging |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.streamDeliveryResources.resources[*].kinesis.contentConfigurations[*].level`<br>`bedrock-agentcore-control/CreateMemory/$.streamDeliveryResources.resources[*].kinesis.contentConfigurations[*].type`<br>`bedrock-agentcore-control/CreateMemory/$.streamDeliveryResources.resources[*].kinesis.dataStreamArn`<br>`bedrock-agentcore-control/UpdateMemory/$.streamDeliveryResources.resources[*].kinesis.contentConfigurations[*].level`<br>`bedrock-agentcore-control/UpdateMemory/$.streamDeliveryResources.resources[*].kinesis.contentConfigurations[*].type`<br>`bedrock-agentcore-control/UpdateMemory/$.streamDeliveryResources.resources[*].kinesis.dataStreamArn`<br>`bedrock-agentcore-control/GetMemory/$.memoryId` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.1 — An Amazon Bedrock AgentCore Memory's IAM execution role should only be assumable by the Amazon Bedrock AgentCore principal on behalf of a trusted resource, AWS Account or AWS Organization

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.1 |
| **Statement** | An Amazon Bedrock AgentCore Memory's IAM execution role should only be assumable by the Amazon Bedrock AgentCore principal on behalf of a trusted resource, AWS Account or AWS Organization |
| **Mitigation Goal** | Confused Deputy Prevention - Service Roles |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.memoryExecutionRoleArn`<br>`bedrock-agentcore-control/UpdateMemory/$.memoryExecutionRoleArn`<br>`bedrock-agentcore-control/GetMemory/$.memoryId` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.2 — An Amazon Bedrock AgentCore Memory should be encrypted with an AWS KMS Customer Managed Key (CMK)

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.2 |
| **Statement** | An Amazon Bedrock AgentCore Memory should be encrypted with an AWS KMS Customer Managed Key (CMK) |
| **Mitigation Goal** | KMS Customer Managed Key (CMK) Encryption |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.encryptionKeyArn`<br>`bedrock-agentcore-control/GetMemory/$.memoryId` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.3 — An Amazon Bedrock AgentCore Memory should be restricted to accessing resources only from approved networks

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.3 |
| **Statement** | An Amazon Bedrock AgentCore Memory should be restricted to accessing resources only from approved networks |
| **Mitigation Goal** | Network Perimeter - Approved Networks |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.memoryExecutionRoleArn`<br>`bedrock-agentcore-control/CreateMemory/$.memoryStrategies[*].customMemoryStrategy.configuration.selfManagedConfiguration.invocationConfiguration.topicArn`<br>`bedrock-agentcore-control/CreateMemory/$.memoryStrategies[*].customMemoryStrategy.configuration.selfManagedConfiguration.invocationConfiguration.payloadDeliveryBucketName`<br>`bedrock-agentcore-control/CreateMemory/$.streamDeliveryResources.resources[*].kinesis.dataStreamArn`<br>`bedrock-agentcore-control/UpdateMemory/$.memoryId`<br>`bedrock-agentcore-control/UpdateMemory/$.memoryExecutionRoleArn`<br>`bedrock-agentcore-control/UpdateMemory/$.memoryStrategies.addMemoryStrategies[*].customMemoryStrategy.configuration.selfManagedConfiguration.invocationConfiguration.topicArn`<br>`bedrock-agentcore-control/UpdateMemory/$.memoryStrategies.addMemoryStrategies[*].customMemoryStrategy.configuration.selfManagedConfiguration.invocationConfiguration.payloadDeliveryBucketName`<br>`bedrock-agentcore-control/UpdateMemory/$.streamDeliveryResources.resources[*].kinesis.dataStreamArn`<br>`bedrock-agentcore-control/GetMemory/$.memoryId` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.4 — An Amazon Bedrock AgentCore Memory should be restricted to accessing only trusted resources

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.4 |
| **Statement** | An Amazon Bedrock AgentCore Memory should be restricted to accessing only trusted resources |
| **Mitigation Goal** | Resource Perimeter - Trusted Resources |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.memoryExecutionRoleArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.5 — An Amazon Bedrock AgentCore Memory should not be tagged with personally identifiable information (PII) or other confidential or sensitive information

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.5 |
| **Statement** | An Amazon Bedrock AgentCore Memory should not be tagged with personally identifiable information (PII) or other confidential or sensitive information |
| **Mitigation Goal** | Resource Tagging - No PII |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.resourceArn`<br>`bedrock-agentcore-control/TagResource/$.tags{key}`<br>`bedrock-agentcore-control/ListTagsForResource/$.resourceArn` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.6 — An Amazon Bedrock AgentCore Memory should be tagged with information that describes the owner and purpose

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.6 |
| **Statement** | An Amazon Bedrock AgentCore Memory should be tagged with information that describes the owner and purpose |
| **Mitigation Goal** | Resource Tagging - Owner and Purpose |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.tags{key}`<br>`bedrock-agentcore-control/TagResource/$.resourceArn`<br>`bedrock-agentcore-control/UntagResource/$.tagKeys[*]`<br>`bedrock-agentcore-control/UntagResource/$.resourceArn`<br>`bedrock-agentcore-control/ListTagsForResource/$.resourceArn`<br>`bedrock-agentcore-control/GetMemory/$.memoryId` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |

### M-Memory.7 — An Amazon Bedrock AgentCore Memory IAM execution role should be accessed only by trusted identities or AWS services acting on behalf of trusted identities

| Attribute | Detail |
|-----------|--------|
| **ID** | M-Memory.7 |
| **Statement** | An Amazon Bedrock AgentCore Memory IAM execution role should be accessed only by trusted identities or AWS services acting on behalf of trusted identities |
| **Mitigation Goal** | Restrict IAM Role Assumption - Service Roles |
| **Request Parameters** | `bedrock-agentcore-control/CreateMemory/$.memoryExecutionRoleArn`<br>`bedrock-agentcore-control/UpdateMemory/$.memoryExecutionRoleArn`<br>`bedrock-agentcore-control/GetMemory/$.memoryId` |
| **Resource Type** | `AWS::BedrockAgentCore::Memory` |
