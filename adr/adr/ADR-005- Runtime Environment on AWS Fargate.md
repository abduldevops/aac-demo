---
id: ADR-005
title: Runtime Environment on AWS Fargate
status: Accepted
date: 2025-11-03
context: Direct Debit Mandate Update Microservice
linkedPolicies:
  - ARC-POLICY-101-control
linkedControls:
  - INFRA-001-control
  - INFRA-006-control
tags: [aws, fargate, deployment, containerization, compliance, directdebit]
supersedes: null
---

## 🏗️ Context
The Direct Debit Mandate Update microservice must run in a **secure, scalable, and managed container environment** that supports policy enforcement, observability, and cost governance.  

Historically, some workloads were deployed on unmanaged EC2 instances or mixed orchestration platforms, resulting in:
- Inconsistent runtime configurations and drift.  
- Complex patching and scaling operations.  
- Gaps in compliance validation and tfsec scanning coverage.  

To achieve full alignment with the enterprise **Cloud-Native Architecture Standard**, the service must operate entirely within the **AWS Fargate** managed runtime model, ensuring immutable, policy-enforced deployments with zero-maintenance infrastructure.

---

## 💡 Decision
The **Direct Debit Mandate Update microservice** will:
1. Deploy as a **containerized service on AWS ECS Fargate**, annotated as `<<fargate>>` in PlantUML diagrams.  
2. Use only **approved base images** tagged `:stable` or equivalent, validated in CI.  
3. Integrate **CloudWatch** for log and metric collection at task level.  
4. Execute **tfsec compliance checks** on all Terraform plans before deployment.  
5. Restrict all inbound traffic to originate from **Amazon API Gateway** over HTTPS.  
6. Store configuration secrets and credentials in **AWS Secrets Manager** (per ADR-002).  
7. Enforce a **desired-state deployment model** through GitHub Actions and OPA validation gates.  

This decision ensures architectural consistency, compliance traceability, and cost visibility across the Fargate-hosted runtime.

---

## ⚙️ Implementation & Enforcement

### Enforcement Mechanisms
- **Policies-as-Code (PaC):**
  - `ARC-POLICY-101-control` – All microservices must be annotated as `<<fargate>>` or reside within a Fargate `System_Boundary`.  

- **Controls-as-Code (CaC):**
  - `INFRA-001-control` – Fargate tasks must use the latest approved image tag (e.g., `:stable`).  
  - `INFRA-006-control` – Terraform plans must pass tfsec checks with no HIGH/Critical issues.  

### Validation Methods
- **OPA/Rego** policies validate that all `.puml` diagrams include the `<<fargate>>` annotation and the correct system boundary.  
- **tfsec** scans run automatically via GitHub Actions to detect insecure or non-compliant Terraform configurations.  
- **ArchUnit** and repository linters confirm runtime configuration consistency and proper container naming conventions.  
- **Runtime posture monitoring** ensures deployed task definitions match approved configurations (image tag, IAM roles, ports, secrets).  

---

## 📈 Consequences
**Positive:**
- Eliminates manual server management and patching.  
- Inherits AWS Fargate scalability, isolation, and operational resilience.  
- Enables continuous compliance with container and infrastructure policies.  
- Reduces configuration drift and enforces immutable deployments.  

**Negative / Trade-offs:**
- Higher per-compute-unit cost compared to EC2 for low-usage workloads.  
- Requires all infrastructure changes to pass through IaC pipelines (slightly longer lead time).  

---

## 🧭 Status & Next Steps
- Applies to all new **Direct Debit** and **Payments** domain microservices.  
- Integrate cost-tracking tags (`@cost-center`, `@platform`) for future **Cost & Value Engineering** analysis (Phase 14).  
- Future ADRs will extend this baseline to multi-region and blue-green deployment patterns.

---

## 🔗 Traceability
| Type | Reference | Description |
|------|------------|-------------|
| **Policy** | `ARC-POLICY-101-control` | Ensures all microservices are declared as `<<fargate>>` within architecture diagrams. |
| **Control** | `INFRA-001-control` | Validates approved Fargate image tags. |
|  | `INFRA-006-control` | Enforces tfsec compliance with no critical findings. |

---

## 📚 Supersession Chain
- **Supersedes:** *None*  
- **Superseded by:** Future ADRs addressing multi-region Fargate scaling or hybrid container strategy.

---
