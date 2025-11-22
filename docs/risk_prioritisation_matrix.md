
# Risk Prioritisation Matrix  
**Version:** 1.0  
**Purpose:** To assess and prioritise vulnerabilities/patches based on *Likelihood* and *Impact*.

---

## 1. Risk Scoring Model

Risk Score = **Likelihood × Impact**

| Score Range | Risk Level |
|-------------|------------|
| 1–3 | Low |
| 4–6 | Medium |
| 8–12 | High |
| 15+ | Critical |

---

## 2. Likelihood Scale

| Likelihood Score | Description |
|------------------|-------------|
| 1 | Rare – very unlikely to be exploited |
| 2 | Possible – could occur but not common |
| 3 | Likely – active exploitation exists |
| 5 | Almost Certain – widely exploited, automated tools exist |

---

## 3. Impact Scale

| Impact Score | Description |
|--------------|-------------|
| 1 | Minimal – negligible business impact |
| 2 | Moderate – limited operational impact |
| 3 | Major – significant disruption |
| 5 | Severe – critical systems affected, data loss |

---

## 4. Risk Matrix

```
              Impact
        |   1   |   2   |   3   |   5
-----------------------------------------
L   1   |   1   |   2   |   3   |   5
i   2   |   2   |   4   |   6   |  10
k   3   |   3   |   6   |   9   |  15
e   5   |   5   |  10   |  15   |  25
```

---

## 5. Risk Classification Table

| Risk Score | Category | Required Action |
|------------|----------|-----------------|
| 1–3 | Low | Acceptable risk, monitor only |
| 4–6 | Medium | Remediate within standard timelines |
| 8–12 | High | Prioritise remediation within 7 days |
| 15–25 | Critical | Immediate action (within 24–72 hrs) |

---

## 6. Example Assessment

| Vulnerability | Likelihood | Impact | Score | Category |
|---------------|------------|--------|--------|----------|
| CVE-2024-0001 | 5 | 5 | 25 | Critical |
| TLS 1.0 Enabled | 3 | 2 | 6 | Medium |
| Outdated Chrome | 2 | 1 | 2 | Low |

---

## 7. Document Control

| Version | Date | Author | Notes |
|--------|------|--------|-------|
| 1.0 | (Insert Date) | (Insert Name) | Initial release |
