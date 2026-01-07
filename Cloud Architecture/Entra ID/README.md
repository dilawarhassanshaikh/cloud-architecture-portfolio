# Microsoft Sentinel - Entra ID Security KQL Queries

A comprehensive collection of KQL (Kusto Query Language) queries for monitoring and detecting security threats in Microsoft Entra ID (formerly Azure AD) using Microsoft Sentinel.

## 📋 Overview

This collection provides production-ready queries to help security teams identify and respond to threats in Entra ID environments. Each query is mapped to MITRE ATT&CK techniques and includes severity ratings.

## 📂 Query Categories

### [01. Authentication & Sign-in Monitoring](kql-queries/01-authentication-monitoring.kql)
Monitor authentication patterns and detect anomalies:
- Failed sign-in attempts detection
- Successful brute force identification  
- Unfamiliar location tracking
- Impossible travel detection
- Multi-user attack patterns

**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)

### [02. Suspicious Activities](kql-queries/02-suspicious-activities.kql)
Identify unusual and potentially malicious behaviors:
- Tor network usage
- Legacy authentication protocols
- Off-hours access
- Password spray attacks
- Suspicious user agents
- Rapid location changes

**MITRE ATT&CK:** T1090 (Proxy), T1110.003 (Password Spraying)

### [03. Privileged Access](kql-queries/03-privileged-access.kql)
Monitor privileged account activities:
- Admin role assignments
- Privileged account sign-ins
- Global administrator activities
- Role removals tracking

**MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1098 (Account Manipulation)

### [04. Account Management](kql-queries/04-account-management.kql)
Track user account lifecycle events:
- User creation and deletion
- Password reset activities
- Guest user invitations
- User property modifications

**MITRE ATT&CK:** T1136.003 (Create Cloud Account), T1531 (Account Access Removal)

### [05. Conditional Access](kql-queries/05-conditional-access.kql)
Monitor conditional access policies:
- Policy failure patterns
- Policy modifications
- MFA registration events

**MITRE ATT&CK:** T1562 (Impair Defenses), T1556 (Modify Authentication Process)

### [06. Risky Users & Sign-ins](kql-queries/06-risky-users-signins.kql)
Leverage Identity Protection signals:
- High-risk sign-ins
- Risk state changes
- Anonymous IP detection
- Leaked credentials

**MITRE ATT&CK:** T1078 (Valid Accounts), T1090 (Proxy)

### [07. Application & Service Principal](kql-queries/07-application-activities.kql)
Monitor application and service principal activities:
- Application registrations
- Service principal sign-ins
- Permission changes
- Secret/certificate updates

**MITRE ATT&CK:** T1550 (Alternate Authentication), T1098 (Account Manipulation)

## 🚀 Getting Started

### Prerequisites

**Required:**
- Microsoft Sentinel workspace
- Entra ID logs flowing into Sentinel
- Log Analytics Reader permissions (minimum)

**Data Connectors to Enable:**
1. Azure Active Directory (Entra ID)
2. Azure AD Identity Protection
3. Office 365 (optional - for enhanced context)

### Verification

Check that data is flowing:
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| take 10
```

## 💻 Usage Guide

### Running Queries in Microsoft Sentinel

1. Navigate to Azure Portal → Microsoft Sentinel
2. Select your workspace
3. Go to **Logs** in the left menu
4. Copy a query from the `kql-queries/` folder
5. Paste into the query window
6. Adjust time ranges as needed
7. Click **Run**

### Creating Analytics Rules

Transform hunting queries into automated detections:

1. Go to **Analytics** in Sentinel
2. Click **+ Create** → **Scheduled query rule**
3. Configure:
   - **Name:** Descriptive rule name
   - **Severity:** Based on threat level
   - **MITRE ATT&CK:** Map to techniques
   - **Query:** Paste from collection
   - **Frequency:** How often to run
   - **Threshold:** Alert conditions
4. Configure incident settings
5. Enable automated responses (optional)
6. Review and create

### Customization Examples

**Adjust time ranges:**
```kql
| where TimeGenerated > ago(24h)  // Last 24 hours
| where TimeGenerated > ago(7d)   // Last 7 days
| where TimeGenerated > ago(30d)  // Last 30 days
```

**Modify thresholds:**
```kql
| where FailedAttempts > 5    // Original
| where FailedAttempts > 10   // More tolerant
| where FailedAttempts > 3    // More sensitive
```

**Filter for specific users:**
```kql
| where UserPrincipalName == "admin@contoso.com"
| where UserPrincipalName contains "admin"
| where UserPrincipalName endswith "@contoso.com"
```

## 📊 Query Development Workflow

```
1. Hunt → Test queries manually to find threats
2. Tune → Adjust thresholds based on your environment
3. Validate → Confirm true/false positive rates
4. Automate → Convert to scheduled analytics rules
5. Respond → Add automated response playbooks
6. Review → Monitor effectiveness and adjust
```

## 🎯 Best Practices

### Before Deployment

✅ **Baseline Your Environment**
- Run queries over 30-90 days
- Understand normal patterns
- Document expected behaviors

✅ **Start Conservative**
- Use higher thresholds initially
- Gradually tighten as you tune
- Monitor false positive rates

✅ **Test in Stages**
- Test in non-production first
- Start with hunting queries
- Convert to rules after validation

### During Operations

✅ **Regular Reviews**
- Weekly: Review high-severity alerts
- Monthly: Tune detection rules
- Quarterly: Update queries for new threats

✅ **Document Exceptions**
- Known service accounts
- Scheduled maintenance windows
- Business-justified anomalies

✅ **Performance Monitoring**
- Track query execution times
- Optimize slow queries
- Use shorter time windows where possible

## 📈 Performance Optimization

### Query Optimization Tips

```kql
// ❌ BAD - Filters late
SigninLogs
| project TimeGenerated, UserPrincipalName, IPAddress
| where TimeGenerated > ago(24h)
| where UserPrincipalName contains "admin"

// ✅ GOOD - Filters early
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName contains "admin"
| project TimeGenerated, UserPrincipalName, IPAddress
```

### Best Practices

1. **Filter early** - Use `where` clauses as soon as possible
2. **Limit columns** - Use `project` to select only needed fields
3. **Aggregate wisely** - Use `summarize` to reduce data volume
4. **Time scope** - Start with shorter time ranges for testing
5. **Avoid wildcards** - Use specific strings when possible

## 🔒 Security Considerations

### Sensitive Data Handling

- Queries don't extract credentials or secrets
- Be careful when sharing query results
- Redact sensitive information in screenshots
- Follow your organization's data handling policies

### Role-Based Access

Recommended permissions:
- **Security Analysts:** Log Analytics Reader
- **Security Engineers:** Log Analytics Contributor
- **SOC Managers:** Sentinel Contributor

## 📚 Additional Resources

### Microsoft Documentation
- [Microsoft Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [KQL Quick Reference](https://docs.microsoft.com/azure/data-explorer/kql-quick-reference)
- [Entra ID Audit Log Reference](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)

### Security Frameworks
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)

### Community Resources
- [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)
- [KQL Cafe](https://github.com/rod-trent/KQLCafe)

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Test your query thoroughly
2. Include clear documentation
3. Map to MITRE ATT&CK techniques
4. Follow the existing format
5. Submit with example output

## 📝 Query Template

When adding new queries, use this template:

```kql
// ============================================================================
// Query Name: [Descriptive Name]
// Description: [What this detects/monitors]
// Use Case: [When/why to use this query]
// MITRE ATT&CK: [Technique ID and name]
// Severity: [Low/Medium/High/Critical]
// False Positive Rate: [Low/Medium/High]
// ============================================================================

[Your KQL query here]

// Expected Output:
// [Describe what the results look like]

// Common False Positives:
// - [List known benign scenarios]

// Tuning Recommendations:
// - [Adjustment suggestions]
```

## ⚠️ Disclaimer

These queries are provided as examples for security monitoring and threat detection. Users should:

- Test thoroughly in their specific environment
- Adjust thresholds based on their baseline
- Validate results before taking action
- Ensure compliance with organizational policies
- Consider privacy and data protection regulations

This collection is maintained as part of ongoing security research and will be updated as new threats emerge and detection techniques improve.

## 📧 Support

- **Issues:** Report bugs or request features via GitHub issues
- **Questions:** Use GitHub discussions for general questions
- **Security:** For security concerns, contact repository maintainers directly

---

**Last Updated:** January 2026  
**Maintained By:** Dilawar Hassan Shaikh  
**Repository:** cloud-architecture-portfolio  
**License:** MIT

---

## Quick Links

- [View All Queries](kql-queries/)
- [MITRE ATT&CK Mapping](#query-categories)
- [Getting Started](#getting-started)
- [Best Practices](#best-practices)
