# API Security Findings (OWASP API Top 10:2023)

| ID | CVSS | Severity | OWASP API | CWE | Finding | Vulnerable build evidence | Secure build |
|---|---|---|---|---|---|---|---|
| API2-a | 9.8 | Critical | API2:2023 Broken Authentication | CWE-347 | JWT 'alg:none' accepted: forge an admin token with no password | `DELETE /api/admin/users/2 with alg:none token -> 200 {'deleted': 2}` | ✅ blocked, feature works |
| API3-a | 8.8 | High | API3:2023 Broken Object Property Level Authorization | CWE-915 | Mass assignment: customer sets own role to admin | `PATCH /api/users/me {role:admin} -> 200 role=admin` | ✅ blocked, feature works |
| API5 | 8.1 | High | API5:2023 Broken Function Level Authorization | CWE-285 | Customer can call admin-only DELETE /api/admin/users | `DELETE /api/admin/users/2 as customer -> 200 {'deleted': 2}` | ✅ blocked, feature works |
| API1 | 6.5 | Medium | API1:2023 Broken Object Level Authorization | CWE-639 | BOLA: read another customer's account by changing the ID | `GET /api/accounts/502 as alice -> 200 {'id': 502, 'owner': 2, 'iban': 'XX00 0000 0000 0502', 'balance': 98000.` | ✅ blocked, feature works |
| API2-b | 6.5 | Medium | API2:2023 Broken Authentication | CWE-307 | No login throttling: unlimited password guessing | `12 wrong passwords -> statuses [401]` | ✅ blocked, feature works |
| API3-b | 4.3 | Medium | API3:2023 Broken Object Property Level Authorization | CWE-213 | Excessive data exposure: response includes SSN digits | `GET /api/accounts/501 fields -> ['balance', 'iban', 'id', 'owner', 'ssn_last4']` | ✅ blocked, feature works |
| API4 | 4.3 | Medium | API4:2023 Unrestricted Resource Consumption | CWE-770 | Unbounded page size: ?limit=100000 returns everything | `GET /api/transactions?limit=100000 -> 5000 rows` | ✅ blocked, feature works |
| API8 | 3.1 | Low | API8:2023 Security Misconfiguration | CWE-942 | Wildcard CORS with credentials flag | `Access-Control-Allow-Origin: *` | ✅ blocked, feature works |
