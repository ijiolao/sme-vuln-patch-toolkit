# TLS Cipher Audit Report (Sample)

**Generated (UTC):** 2025-11-22 11:32 UTC  
**Source CSV:** `tls_cipher_audit_sample.csv` (example)

---

## 1. Summary

- Total targets scanned: **3**  
- Targets with **weak protocols** detected: **0**  
- Targets with **weak ciphers** detected: **1**  

### Overall Assessment

Your external TLS footprint is **partially aligned** with the baseline:

- Most endpoints negotiate modern TLS versions (TLS 1.2 / 1.3).  
- One endpoint still presents **legacy / weak cipher options** that should be reviewed and hardened.  

---

## 2. Per-Target Results

| Target              | TLS Version | Cipher Suite                  | Bits | Weak Protocol | Weak Cipher | Notes                                   |
|---------------------|------------|-------------------------------|------|---------------|-------------|-----------------------------------------|
| example.com:443     | TLSv1.3    | TLS_AES_256_GCM_SHA384        | 256  | No            | No          | OK – modern protocol and strong cipher. |
| api.example.com:443 | TLSv1.2    | ECDHE-RSA-AES256-GCM-SHA384   | 256  | No            | No          | OK – aligned with current baseline.     |
| legacy.example.com:443 | TLSv1.2 | ECDHE-RSA-DES-CBC3-SHA        | 112  | No            | Yes         | Uses 3DES – considered weak, remove.    |

---

## 3. Findings & Recommendations

### 3.1 Strong Endpoints

The following endpoints are considered **aligned with the TLS & Misconfiguration Baseline**:

- `example.com:443`  
- `api.example.com:443`  

They use modern TLS versions with strong AEAD ciphers and 256-bit keys.

### 3.2 Weak / Legacy Configuration

**Endpoint:** `legacy.example.com:443`  

- Negotiated cipher: `ECDHE-RSA-DES-CBC3-SHA`  
- Effective key length: **112 bits (3DES)**  
- Status: **Flagged as WEAK_CIPHER**  

**Recommendations:**

1. Disable legacy cipher suites using **3DES**, **RC4**, and any **EXPORT** or **NULL** variants.  
2. Prefer only the following families where possible:  
   - `TLS_AES_*` (TLS 1.3)  
   - `ECDHE-RSA-AES128-GCM-SHA256`  
   - `ECDHE-RSA-AES256-GCM-SHA384`  
3. Re-test this endpoint using `tls_cipher_audit.py` and/or an external scanner (e.g. SSL Labs).  

---

## 4. How to Reproduce This Report

1. Create a `targets.txt` file (example):

   ```text
   example.com:443
   api.example.com:443
   legacy.example.com:443
   ```

2. Run the TLS audit tool:

   ```bash
   python tls_cipher_audit.py --input targets.txt --output tls_cipher_audit_results.csv
   ```

3. (Optional) In your toolkit, you can build a small script to parse the CSV and render a report similar to this sample.

---

_This is a **sample** report for documentation and demo purposes. Replace hostnames and results with your real environment when using the tool._
