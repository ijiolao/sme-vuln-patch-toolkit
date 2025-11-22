
# Change Categorisation Guide  
**Version:** 1.0  
**Purpose:** This guide helps SMEs categorise changes consistently within IT and security operations to reduce risk and maintain compliance with ISO 27001, NIST CSF, and SOC 2 requirements.

---

## 1. Overview of Change Categories

Changes are grouped into three main categories:

### **1. Standard Change**
Pre-approved, low-risk, repeatable changes with documented procedures.

Examples:  
- Adding new user accounts  
- Applying routine OS updates already validated  
- Restarting non-critical services  
- Updating antivirus definitions  
- Renewing SSL certificates (if no config change)

Characteristics:  
- No approval required beyond workflow  
- Fully documented & predictable  
- No downtime expected  

---

### **2. Normal Change**
Moderate risk, requiring assessment, scheduling, and approval.

Examples:  
- OS patches for servers in production  
- Updating firewall rules  
- Modifying IAM permissions  
- Application updates impacting user experience  
- Database schema updates

Characteristics:  
- Requires formal approval  
- May require downtime  
- Needs rollback plan  
- Requires testing in non-production  

---

### **3. Emergency Change**
High-risk, immediate changes required to fix issues or prevent major incidents.

Examples:  
- Emergency patches for zero-day vulnerabilities  
- Fixing a downed production system  
- Containment actions during an active cyber incident  
- Revoking compromised credentials

Characteristics:  
- Implemented immediately  
- Approval may be retrospective  
- Must be reviewed via PIR afterward  

---

## 2. Risk-Based Categorisation Criteria

| Factor | Standard | Normal | Emergency |
|--------|----------|---------|------------|
| Risk Level | Low | Medium–High | Critical |
| Downtime | None | Possible | Immediate |
| Testing Required | No | Yes | If possible |
| Approval | Not required | Required | Retrospective |
| Rollback Plan | Not required | Required | Required |

---

## 3. Decision Tree

Use this decision tree to determine change category:

1. **Does it fix an active incident or service outage?**  
   → Emergency Change

2. **Does it introduce new risk or require downtime?**  
   → Normal Change

3. **Is it repeatable, low-risk, and previously validated?**  
   → Standard Change  

If uncertain, classify as **Normal Change**.

---

## 4. Documentation Requirements

### **Standard Change**
- Logged in change system  
- Pre-approved procedure  
- No additional risk assessment required  

### **Normal Change**
- Full change form required  
- Risk assessment  
- Rollback plan  
- Scheduling with business  
- Testing evidence  

### **Emergency Change**
- Immediate documentation  
- Root cause analysis  
- PIR (Post Implementation Review)  
- Retrospective approval  

---

## 5. Alignment With Standards

### **ISO 27001:2022 — A.8.32 Change Management**
- Requires changes to be controlled, authorised, and documented  
- Supports Standard/Normal/Emergency classifications  

### **NIST CSF — PR.IP-3**
- Change control processes should be in place and followed  

### **SOC 2 — CC8.1**
- Requires consistent change approval and documentation  

---

## 6. Document Control

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | (Insert Date) | (Insert Name) | Initial Release |

