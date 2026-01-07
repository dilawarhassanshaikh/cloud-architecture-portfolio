# Microsoft Sentinel - Entra ID Security KQL Queries

A curated collection of KQL (Kusto Query Language) queries for Microsoft Sentinel focusing on Entra ID (Azure AD) security monitoring and threat detection.

## 📋 Table of Contents

- [Overview](#overview)
- [Query Categories](#query-categories)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](#contributing)

## 🎯 Overview

This repository contains production-ready KQL queries designed to help security teams monitor and detect threats in Microsoft Entra ID environments using Microsoft Sentinel. Each query is optimized for performance and includes clear documentation.

## 📂 Query Categories

### Authentication & Sign-in Monitoring
- Failed sign-in attempts by user
- Successful sign-ins after multiple failures
- Sign-ins from unfamiliar locations
- Impossible travel detection

### Suspicious Activities
- Sign-ins from Tor network
- Legacy authentication usage
- Sign-ins outside business hours
- Distributed password spray attacks

### Privileged Access
- Admin role assignments
- Privileged account sign-ins
- Global admin activity monitoring

### Account Management
- Recently created user accounts
- Deleted user accounts
- Password reset activities
- Guest user activities

### Conditional Access
- Conditional access failures
- Policy changes tracking

### Risky Users & Sign-ins
- High-risk sign-ins
- Risk state changes
- Anonymous IP address sign-ins

### Application & Service Principal Activities
- New application registrations
- Service principal sign-ins
- Application permission changes

## 🚀 Getting Started

### Prerequisites
- Microsoft Sentinel workspace
- Entra ID logs configured to flow into Sentinel
- Appropriate permissions to run queries

### Required Data Connectors
Ensure the following connectors are enabled in your Sentinel workspace:
- Azure Active Directory (Entra ID)
- Azure Active Directory Identity Protection

## 💻 Usage

### Running Queries in Sentinel

1. Navigate to your Microsoft Sentinel workspace in Azure Portal
2. Go to **Logs** section
3. Copy the desired query from the query files
4. Paste into the query editor
5. Adjust time ranges and thresholds as needed
6. Click **Run**

### Customization Tips
```kql
// Adjust time range
| where TimeGenerated > ago(24h)  // Change to 7d, 30d, etc.

// Modify thresholds
| where FailedAttempts > 5  // Adjust based on your baseline
```

## 📊 Performance Considerations

- Start with shorter time ranges when testing queries
- Use `summarize` operators to reduce result set size
- Monitor query performance in Sentinel's query statistics

## 🔒 Security Best Practices

1. **Baseline your environment** - Run queries over 30-90 days to understand normal patterns
2. **Adjust thresholds** - Modify detection thresholds based on your organization's size
3. **Test before production** - Validate queries in a test workspace first
4. **Regular reviews** - Update queries as your environment evolves

## 📚 Additional Resources

- [Microsoft Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [KQL Quick Reference](https://docs.microsoft.com/azure/data-explorer/kql-quick-reference)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## ⚠️ Disclaimer

These queries are provided as examples for security monitoring and threat detection. Always test queries in your specific environment before using in production.

---

**Maintained by:** Dilawar Hassan Shaikh  
**Last Updated:** January 2026
