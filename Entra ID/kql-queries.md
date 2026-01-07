# Entra ID Security KQL Queries for Microsoft Sentinel

> **Last Updated:** January 2026  
> **Author:** Dilawar Hassan Shaikh

---

## Table of Contents

1. [Authentication & Sign-in Monitoring](#1-authentication--sign-in-monitoring)
2. [Suspicious Activities](#2-suspicious-activities)
3. [Privileged Access](#3-privileged-access)
4. [Account Management](#4-account-management)
5. [Conditional Access](#5-conditional-access)
6. [Risky Users & Sign-ins](#6-risky-users--sign-ins)
7. [Application & Service Principal Activities](#7-application--service-principal-activities)

---

## 1. Authentication & Sign-in Monitoring

### 1.1 Failed Sign-in Attempts by User
**Purpose:** Detect users with multiple failed sign-in attempts (potential brute force)  
**MITRE ATT&CK:** T1110 - Brute Force  
**Severity:** Medium

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize FailedAttempts = count(), 
            IPAddresses = make_set(IPAddress),
            Locations = make_set(Location)
            by UserPrincipalName, AppDisplayName
| where FailedAttempts > 5
| order by FailedAttempts desc
```

### 1.2 Successful Sign-ins After Multiple Failures
**Purpose:** Identify potential successful brute force attacks  
**MITRE ATT&CK:** T1110.001 - Password Guessing  
**Severity:** High

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| order by UserPrincipalName, TimeGenerated asc
| extend PreviousResultType = prev(ResultType, 1)
| where ResultType == "0" and PreviousResultType != "0"
| summarize FailedBeforeSuccess = countif(PreviousResultType != "0"),
            FirstFailure = min(TimeGenerated),
            SuccessTime = max(TimeGenerated)
            by UserPrincipalName, IPAddress
| where FailedBeforeSuccess > 3
```

### 1.3 Sign-ins from Unfamiliar Locations
**Purpose:** Detect sign-ins from countries not seen in the last 14 days  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Medium

```kql
let KnownLocations = SigninLogs
| where TimeGenerated between(ago(14d)..ago(1d))
| summarize by UserPrincipalName, Location;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| join kind=leftanti KnownLocations on UserPrincipalName, Location
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName, DeviceDetail
```

### 1.4 Impossible Travel Detection
**Purpose:** Identify sign-ins from geographically distant locations within a short time  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** High

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, Location, IPAddress, Latitude, Longitude
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend NextLocation = next(Location, 1), 
         NextTime = next(TimeGenerated, 1),
         NextUser = next(UserPrincipalName, 1)
| where UserPrincipalName == NextUser and Location != NextLocation
| extend TimeDiffMinutes = datetime_diff('minute', NextTime, TimeGenerated)
| where TimeDiffMinutes < 60 and TimeDiffMinutes > 0
```

### 1.5 Multiple Failed Sign-ins from Same IP
**Purpose:** Detect potential credential stuffing attacks  
**MITRE ATT&CK:** T1110.003 - Password Spraying  
**Severity:** High

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailedUsers = dcount(UserPrincipalName),
            AttemptedAccounts = make_set(UserPrincipalName),
            TotalAttempts = count()
            by IPAddress, Location, bin(TimeGenerated, 5m)
| where FailedUsers > 5
| order by FailedUsers desc
```

---

## 2. Suspicious Activities

### 2.1 Sign-ins from Tor Network
**Purpose:** Detect authentication attempts from Tor exit nodes  
**MITRE ATT&CK:** T1090 - Proxy  
**Severity:** High

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where NetworkLocationDetails contains "tor" 
    or NetworkLocationDetails contains "anonymizer"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName
```

### 2.2 Legacy Authentication Usage
**Purpose:** Identify use of legacy authentication protocols (security risk)  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Medium

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed in ("Other clients", "IMAP", "POP", "SMTP", 
                          "Exchange ActiveSync", "Authenticated SMTP")
| summarize Count = count(), 
            LastSeen = max(TimeGenerated),
            IPAddresses = make_set(IPAddress)
            by UserPrincipalName, ClientAppUsed
| order by Count desc
```

### 2.3 Sign-ins Outside Business Hours
**Purpose:** Detect authentication during non-business hours  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Low

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 7 or Hour > 19
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName, DeviceDetail
```

### 2.4 Distributed Password Spray Attack
**Purpose:** Identify potential password spray attacks across multiple users  
**MITRE ATT&CK:** T1110.003 - Password Spraying  
**Severity:** Critical

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize UniqueUsers = dcount(UserPrincipalName),
            Users = make_set(UserPrincipalName),
            AttemptCount = count()
            by IPAddress, bin(TimeGenerated, 5m)
| where UniqueUsers > 10 and AttemptCount > 20
| order by AttemptCount desc
```

### 2.5 Suspicious User Agent Strings
**Purpose:** Detect unusual or automated tools accessing Entra ID  
**MITRE ATT&CK:** T1189 - Drive-by Compromise  
**Severity:** Medium

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserAgent contains "python" 
    or UserAgent contains "curl"
    or UserAgent contains "powershell"
    or UserAgent contains "bot"
| project TimeGenerated, UserPrincipalName, UserAgent, IPAddress, ResultType
```

---

## 3. Privileged Access

### 3.1 Admin Role Assignments
**Purpose:** Track when administrative roles are assigned to users  
**MITRE ATT&CK:** T1098 - Account Manipulation  
**Severity:** High

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend AssignedUser = tostring(TargetResources[1].userPrincipalName)
| extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName contains "Admin" or RoleName contains "Director"
| project TimeGenerated, RoleName, AssignedUser, AssignedBy, Result
```

### 3.2 Privileged Account Sign-ins
**Purpose:** Monitor authentication by users with administrative privileges  
**MITRE ATT&CK:** T1078.004 - Cloud Accounts  
**Severity:** Medium

```kql
let AdminUsers = IdentityInfo
| where AssignedRoles contains "Admin"
| distinct AccountUPN;
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (AdminUsers)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, DeviceDetail
| order by TimeGenerated desc
```

### 3.3 Global Admin Activity
**Purpose:** Track all activities performed by Global Administrators  
**MITRE ATT&CK:** T1078.004 - Cloud Accounts  
**Severity:** High

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner (
    IdentityInfo
    | where AssignedRoles contains "Global Administrator"
    | distinct AccountUPN
) on $left.InitiatorUPN == $right.AccountUPN
| project TimeGenerated, OperationName, InitiatorUPN, TargetResources, Result
```

### 3.4 Privileged Role Removals
**Purpose:** Detect when admin roles are removed from users  
**MITRE ATT&CK:** T1098 - Account Manipulation  
**Severity:** High

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Remove member from role"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend RemovedUser = tostring(TargetResources[1].userPrincipalName)
| extend RemovedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, RoleName, RemovedUser, RemovedBy, Result
```

---

## 4. Account Management

### 4.1 Recently Created User Accounts
**Purpose:** List user accounts created in the specified timeframe  
**MITRE ATT&CK:** T1136.003 - Create Account: Cloud Account  
**Severity:** Medium

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add user"
| extend NewUser = tostring(TargetResources[0].userPrincipalName)
| extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, NewUser, CreatedBy, Result, AdditionalDetails
```

### 4.2 Deleted User Accounts
**Purpose:** Track recently deleted user accounts  
**MITRE ATT&CK:** T1531 - Account Access Removal  
**Severity:** Medium

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Delete user"
| extend DeletedUser = tostring(TargetResources[0].userPrincipalName)
| extend DeletedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, DeletedUser, DeletedBy, Result
```

### 4.3 Password Reset Activities
**Purpose:** Monitor password resets, particularly for privileged accounts  
**MITRE ATT&CK:** T1098 - Account Manipulation  
**Severity:** Medium

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Reset password (by admin)", "Change password (self-service)")
| extend AffectedUser = tostring(TargetResources[0].userPrincipalName)
| extend InitiatorUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, AffectedUser, InitiatorUser, Result
```

### 4.4 Guest User Invitations
**Purpose:** Track guest user invitations and activities  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Low

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Invite external user", "Redeem external user invite")
| extend GuestEmail = tostring(TargetResources[0].userPrincipalName)
| extend InvitedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, GuestEmail, InvitedBy, Result
```

### 4.5 User Property Changes
**Purpose:** Detect modifications to user account properties  
**MITRE ATT&CK:** T1098 - Account Manipulation  
**Severity:** Low

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Update user"
| extend ModifiedUser = tostring(TargetResources[0].userPrincipalName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ModifiedUser, ModifiedBy, TargetResources, Result
```

---

## 5. Conditional Access

### 5.1 Conditional Access Failures
**Purpose:** Identify sign-ins blocked by conditional access policies  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Low

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "53003"
| summarize FailureCount = count(),
            Users = make_set(UserPrincipalName)
            by IPAddress, Location
| order by FailureCount desc
```

### 5.2 Conditional Access Policy Changes
**Purpose:** Track modifications to conditional access policies  
**MITRE ATT&CK:** T1562 - Impair Defenses  
**Severity:** High

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where Category == "Policy"
| where OperationName contains "conditional access"
| extend PolicyName = tostring(TargetResources[0].displayName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, PolicyName, ModifiedBy, Result
```

### 5.3 MFA Registration Activity
**Purpose:** Monitor Multi-Factor Authentication registration events  
**MITRE ATT&CK:** T1556 - Modify Authentication Process  
**Severity:** Medium

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("User registered security info", "User deleted security info")
| extend AffectedUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, AffectedUser, Result
```

---

## 6. Risky Users & Sign-ins

### 6.1 High Risk Sign-ins
**Purpose:** Detect sign-ins flagged as high risk by Identity Protection  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** High

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn == "high" or RiskLevelAggregated == "high"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskDetail, RiskEventTypes
```

### 6.2 Users with Risk State Changes
**Purpose:** Track when users are flagged or unflagged as risky  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Medium

```kql
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| summarize Events = count(), 
            RiskTypes = make_set(RiskEventType),
            LastDetected = max(TimeGenerated)
            by UserPrincipalName, RiskState
| order by LastDetected desc
```

### 6.3 Anonymous IP Address Sign-ins
**Purpose:** Identify sign-ins from anonymous proxy services  
**MITRE ATT&CK:** T1090 - Proxy  
**Severity:** Medium

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskEventTypes contains "anonymizedIPAddress"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
```

### 6.4 Leaked Credentials Detection
**Purpose:** Detect sign-ins with leaked credentials  
**MITRE ATT&CK:** T1078 - Valid Accounts  
**Severity:** Critical

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskEventTypes contains "leakedCredentials"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskDetail
```

---

## 7. Application & Service Principal Activities

### 7.1 New Application Registrations
**Purpose:** Track newly registered applications  
**MITRE ATT&CK:** T1550 - Use Alternate Authentication Material  
**Severity:** Medium

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, AppName, CreatedBy, Result
```

### 7.2 Service Principal Sign-ins
**Purpose:** Monitor authentication by service principals and applications  
**MITRE ATT&CK:** T1078.004 - Cloud Accounts  
**Severity:** Low

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| summarize SignInCount = count(),
            UniqueIPs = dcount(IPAddress)
            by ServicePrincipalName, AppId
| order by SignInCount desc
```

### 7.3 Application Permission Changes
**Purpose:** Track changes to application permissions  
**MITRE ATT&CK:** T1098 - Account Manipulation  
**Severity:** High

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add app role assignment to service principal", 
                          "Add delegated permission grant")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, AppName, ModifiedBy, Result
```

### 7.4 Service Principal Secret Changes
**Purpose:** Detect when service principal secrets/certificates are added or updated  
**MITRE ATT&CK:** T1098 - Account Manipulation  
**Severity:** High

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add service principal credentials", 
                          "Update service principal credentials")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, AppName, ModifiedBy, Result
```

---

## Usage Tips

### Adjusting Time Ranges
```kql
// Change from 24 hours to 7 days
| where TimeGenerated > ago(7d)

// Change to 30 days
| where TimeGenerated > ago(30d)

// Specific date range
| where TimeGenerated between(datetime(2026-01-01)..datetime(2026-01-07))
```

### Modifying Thresholds
```kql
// Change failed attempt threshold
| where FailedAttempts > 10  // Instead of 5

// Adjust time window for impossible travel
| where TimeDiffMinutes < 120  // Instead of 60
```

### Filtering for Specific Users
```kql
// Add filter for specific user
| where UserPrincipalName == "user@domain.com"

// Filter for domain
| where UserPrincipalName endswith "@yourdomain.com"
```

---

## Performance Optimization

1. **Limit time ranges** - Use shorter time windows when testing
2. **Use summarize early** - Aggregate data before other operations
3. **Filter early** - Apply where clauses as early as possible
4. **Avoid wildcards** - Use specific strings when possible

---

**For support or questions, please open an issue in the repository.**
