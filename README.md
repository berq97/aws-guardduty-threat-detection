# AWS Threat Detection & Automated Response — GuardDuty, Security Hub, EventBridge & Lambda

## Objective

Built a threat detection and automated response pipeline using Amazon GuardDuty for managed threat detection, AWS Security Hub for centralized findings aggregation, and Amazon EventBridge to route findings to two parallel response paths: real-time email alerting (via SNS) and automated, structured incident logging (via a Lambda function writing to DynamoDB). This lab builds directly on the CloudTrail/EventBridge/SNS foundation from Lab 1, extending it to a managed detection service rather than custom-defined event patterns.

## Architecture

```
GuardDuty (continuous threat detection)
   |
   |--> Security Hub (findings aggregation + foundational security checks)
   |
   |--> EventBridge Rule (filters findings by severity >= 4.0, i.e. Medium/High/Critical)
            |
            |--> Target 1: SNS ("SecurityAlarms" topic) --> Email notification
            |
            |--> Target 2: Lambda ("GuardDutyFindingLogger") --> DynamoDB ("SecurityFindings" table)
```

A single EventBridge rule fans out to two independent targets from the same triggering event — one for immediate human notification, one for automated, queryable incident logging.

## What I Built

### 1. GuardDuty (Threat Detection)

- Enabled GuardDuty with all detection features active (including extended integrations covering EC2, ECR, and Lambda resources via AWS Inspector, which GuardDuty provisions automatically).
- Used GuardDuty's built-in sample finding generator to produce realistic findings spanning all severity levels and finding types, without needing to simulate actual malicious activity against real infrastructure.

### 2. Security Hub (Findings Aggregation)

- Enabled Security Hub with the AWS Foundational Security Best Practices standard.
- Confirmed Security Hub automatically ingests GuardDuty findings alongside its own foundational checks, giving a single aggregated view (Security Hub's dashboard reflects a cumulative historical view over a selected time window, which is why its totals differ from GuardDuty's live findings count — see Key Findings below).

### 3. EventBridge Rule — Severity-Filtered Routing (`GuardDutyMediumHigh-Rule`)

- Built an EventBridge rule matching `source: aws.guardduty`, `detail-type: GuardDuty Finding`, filtered to only findings with `severity >= 4.0` (Medium, High, and Critical) — deliberately excluding Low-severity findings to avoid alert fatigue, a standard practice in real security operations.
- GuardDuty finding severity is a numeric field; EventBridge content filtering for numeric ranges required an explicit enumerated list of matching values in the pattern (rather than a `>=` range operator), which I confirmed via AWS documentation and community references before building the rule.
- Routed to two targets from this single rule:
  - **SNS** (`SecurityAlarms` topic, reused from Lab 1) for immediate email notification
  - **Lambda** (`GuardDutyFindingLogger`) for automated structured logging

### 4. Lambda Automated Response (`GuardDutyFindingLogger`)

- Python 3.13 Lambda function triggered directly by the EventBridge rule as a second target.
- Parses the incoming GuardDuty finding event, extracts key fields (`findingId`, `type`, `severity`, `accountId`, `region`, `title`, `description`, `createdAt`), and writes a structured record into a DynamoDB table (`SecurityFindings`), adding a `loggedAt` timestamp for audit purposes.
- **Execution role scoped to least privilege**: rather than attaching the broad `AmazonDynamoDBFullAccess` managed policy, I created a custom inline policy granting only `dynamodb:PutItem` on the specific `SecurityFindings` table ARN — nothing more. This keeps the Lambda's blast radius minimal even if its code or trigger were ever compromised.
- EventBridge's own permission to invoke the Lambda was handled via a separate, auto-generated execution role scoped specifically to this one rule invoking this one function — distinct from the Lambda's own execution role, which controls what the function can do once running.

## Testing & Verification

- Generated GuardDuty sample findings (spanning all severities and finding types) to produce realistic test events without needing to simulate actual threats.
- Verified the EventBridge rule's severity filter is functioning correctly: out of a batch of sample findings (5 Critical, 60 High, 48 Medium, 16 Low), only the Medium-and-above findings (113 of 129) triggered the rule — Low-severity findings were correctly excluded.
- Confirmed SNS email delivery for triggered findings, including full JSON payload showing `source: aws.guardduty`, finding `type`, and `severity`.
- Confirmed Lambda execution via CloudWatch Logs — each invocation showed a clean `INIT_START/START → Logged finding [id] with severity [n] → END → REPORT` cycle with no errors.
- Confirmed DynamoDB writes directly in the table: inspected a full item to verify every extracted field (`findingId`, `accountId`, `createdAt`, `description`, `severity`, `title`, `type`, `loggedAt`) was populated correctly and matched the source finding.
- **Note on testing process**: an early round of testing accidentally left duplicate sample findings in GuardDuty after clicking "Generate sample findings" multiple times across sessions, temporarily inflating the findings count to 444 and triggering a large batch of SNS emails. This was diagnosed, archived, and cleanly regenerated before final verification — included here as an honest account of the debugging/cleanup process, not just the final working state.

## Key Technical Findings

- **GuardDuty finding severity is numeric**, and EventBridge's content-based filtering for numeric thresholds (e.g. "severity >= 4.0") requires an explicit list of matching values in the event pattern rather than a native range/comparison operator in this context — a syntax quirk worth knowing before building similar rules.
- **GuardDuty console JSON and EventBridge event JSON use different field casing.** The GuardDuty console displays findings with PascalCase fields (`Severity`, `Type`, `AccountId`), while the same finding delivered through EventBridge uses lowercase/camelCase fields inside the `detail` object (`severity`, `type`, `accountId`). Building an event pattern or sample event against the wrong casing silently fails to match.
- **Enabling GuardDuty's "all features" option also provisions AWS Inspector** in the background (visible as auto-created `DO-NOT-DELETE-AmazonInspector...` managed EventBridge rules), which routes EC2, ECR, and Lambda events to Inspector for vulnerability scanning. This happens without an extra explicit setup step and is worth knowing before assuming every resource in your account was created manually.
- **Security Hub's dashboard totals reflect a cumulative, time-windowed historical view** (e.g., "3 months") rather than GuardDuty's live/current findings count — the two services will show different numbers even when correctly integrated, because they're answering different questions ("what's active right now" vs. "what happened over this period").

## Operational Security Practices Followed

- Scoped the Lambda's execution role to a single DynamoDB action (`PutItem`) on a single table ARN, rather than using a broad managed policy — demonstrating least-privilege practice even in a fast-moving lab environment.
- Separated the two distinct IAM concerns involved in Lambda + EventBridge integration: the Lambda's own execution role (what the function can do) versus EventBridge's invocation role (permission to trigger the function), each scoped independently.
- Used GuardDuty's built-in sample finding generator for testing rather than attempting to simulate real malicious activity against live infrastructure.

## What I'd Add Next

- **Extend automated response with real remediation**, not just logging — for example, isolating a flagged EC2 instance via a quarantine security group. This is intentionally deferred to align with Lab 4 (Terraform-provisioned VPC/EC2 infrastructure), so remediation logic can be tested against real infrastructure rather than a throwaway instance built solely for this test.
- Add a **DynamoDB Stream + downstream processing** (e.g., aggregating findings by type/severity over time for trend reporting) rather than only storing individual records.
- Consider **EventBridge Archive and Replay** to demonstrate re-processing historical findings against updated Lambda logic without needing to regenerate GuardDuty samples.
