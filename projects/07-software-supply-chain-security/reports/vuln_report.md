# Dependency Vulnerability Report

**Policy: FAIL** · 7 pinned components · 58 known vulnerabilities · 2 unpinned

## Upgrade plan

| Component | Installed | Vulns | Worst severity | Upgrade to |
|---|---|---|---|---|
| axios | 0.21.0 | 25 | HIGH | >= 0.33.0 |
| lodash | 4.17.15 | 6 | HIGH | latest (> 4.17.23) |
| urllib3 | 1.24.1 | 13 | UNKNOWN | >= 2.8.0 |
| jinja2 | 2.10 | 6 | UNKNOWN | >= 3.1.6 |
| requests | 2.19.1 | 5 | UNKNOWN | >= 2.33.0 |
| pyyaml | 5.3 | 3 | UNKNOWN | >= 5.4 |

## All advisories

| Component | Advisory | CVE | Severity | Fixed in | Summary |
|---|---|---|---|---|---|
| axios@0.21.0 | GHSA-cph5-m8f7-6c5x | - | HIGH | 0.21.2 | axios Inefficient Regular Expression Complexity vulnerability |
| axios@0.21.0 | GHSA-jr5f-v2jv-69x6 | - | HIGH | 0.30.0 | axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL |
| axios@0.21.0 | GHSA-hfxv-24rg-xrqf | - | HIGH | > 0.31.1 | Axios: Regular Expression Denial of Service (ReDoS) via Cookie Name Injection |
| axios@0.21.0 | GHSA-p92q-9vqr-4j8v | - | HIGH | > 0.31.1 | Axios: Proxy-Authorization Credential Leak to Origin Server Across HTTP-to-HTTPS Redirect in Axios Node.js HTTP Adapter |
| axios@0.21.0 | GHSA-j5f8-grm9-p9fc | - | HIGH | > 0.31.1 | Axios: Proxy-Authorization header leaks to redirect target when proxy is re-evaluated to direct connection |
| axios@0.21.0 | GHSA-3g43-6gmg-66jw | - | HIGH | 0.31.1 | axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge |
| axios@0.21.0 | GHSA-pmwg-cvhr-8vh7 | - | HIGH | > 0.31.0 | Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Protection Bypassed via RFC 1122 Loopback Subnet (127.0.0.0/8) in Ax |
| axios@0.21.0 | GHSA-pf86-5x62-jrwf | - | HIGH | > 0.31.0 | Axios: Prototype Pollution Gadgets - Response Tampering, Data Exfiltration, and Request Hijacking |
| axios@0.21.0 | GHSA-6chq-wfr3-2hj9 | - | HIGH | > 0.31.0 | Axios: Header Injection via Prototype Pollution |
| axios@0.21.0 | GHSA-43fc-jf86-j433 | - | HIGH | > 0.30.2 | Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig |
| axios@0.21.0 | GHSA-pjwm-pj3p-43mv | - | HIGH | > 0.31.1 | axios's shouldBypassProxy does not recognize IPv4-mapped IPv6 addresses, allowing NO_PROXY bypass (incomplete fix for CV |
| lodash@4.17.15 | GHSA-35jh-r3h4-6jhm | - | HIGH | 4.17.21 | Command Injection in lodash |
| lodash@4.17.15 | GHSA-p6mc-m468-83gw | - | HIGH | 4.17.19 | Prototype Pollution in lodash |
| lodash@4.17.15 | GHSA-r5fr-rjxr-66jc | - | HIGH | > 4.17.23 | lodash vulnerable to Code Injection via `_.template` imports key names |
| axios@0.21.0 | GHSA-fvcv-3m26-pcqx | - | MODERATE | 0.31.0 | Axios has Unrestricted Cloud Metadata Exfiltration via Header Injection Chain |
| axios@0.21.0 | GHSA-62hf-57xw-28j9 | - | MODERATE | > 0.31.0 | Axios: unbounded recursion in toFormData causes DoS via deeply nested request data |
| axios@0.21.0 | GHSA-898c-q2cr-xwhg | - | MODERATE | > 0.31.1 | axios has DoS & Header Injection via Prototype Pollution Read-Side Gadgets in axios merge functions |
| axios@0.21.0 | GHSA-3p68-rc4w-qgx5 | - | MODERATE | 0.31.0 | Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF |
| axios@0.21.0 | GHSA-4w2v-q235-vp99 | - | MODERATE | 0.21.1 | Axios vulnerable to Server-Side Request Forgery |
| axios@0.21.0 | GHSA-w9j2-pvgh-6h63 | - | MODERATE | > 0.31.0 | Axios: Authentication Bypass via Prototype Pollution Gadget in `validateStatus` Merge Strategy |
| axios@0.21.0 | GHSA-m7pr-hjqh-92cm | - | MODERATE | > 0.31.0 | Axios: no_proxy bypass via IP alias allows SSRF |
| axios@0.21.0 | GHSA-5c9x-8gcm-mpgx | - | MODERATE | > 0.31.0 | Axios' HTTP adapter-streamed uploads bypass maxBodyLength when maxRedirects: 0 |
| axios@0.21.0 | GHSA-vf2m-468p-8v99 | - | MODERATE | > 0.31.0 | Axios: HTTP adapter streamed responses bypass maxContentLength |
| axios@0.21.0 | GHSA-xx6v-rp6x-q39c | - | MODERATE | > 0.31.0 | Axios: XSRF Token Cross-Origin Leakage via Prototype Pollution Gadget in `withXSRFToken` Boolean Coercion |
| axios@0.21.0 | GHSA-wf5p-g6vw-rhxx | - | MODERATE | 0.28.0 | Axios Cross-Site Request Forgery Vulnerability |
| axios@0.21.0 | GHSA-mmx7-hfxf-jppx | - | MODERATE | 0.33.0 | Axios: Prototype pollution gadgets can alter axios request construction |
| axios@0.21.0 | GHSA-7q8q-rj6j-mhjq | - | MODERATE | 0.33.0 | Axios: Nested axios option objects can consume polluted prototype values |
| lodash@4.17.15 | GHSA-29mw-wpgm-hmr9 | - | MODERATE | 4.17.21 | Regular Expression Denial of Service (ReDoS) in lodash |
| lodash@4.17.15 | GHSA-xxjr-mmjv-4gpg | - | MODERATE | > 4.17.22 | Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions |
| lodash@4.17.15 | GHSA-f23m-r3pf-42rh | - | MODERATE | > 4.17.23 | lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit` |
| axios@0.21.0 | GHSA-xhjh-pmcv-23jw | - | LOW | > 0.31.0 | Axios: Null Byte Injection via Reverse-Encoding in AxiosURLSearchParams |
| jinja2@2.10 | PYSEC-2021-66 | CVE-2020-28493 | UNKNOWN | 2.11.3 | This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the `_punctuation |
| jinja2@2.10 | PYSEC-2019-217 | CVE-2019-10906 | UNKNOWN | 2.10.1 | In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape. |
| jinja2@2.10 | GHSA-h5c8-rqwp-cp95 | CVE-2024-22195 | UNKNOWN | 3.1.3 | The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain sp |
| jinja2@2.10 | GHSA-h75v-3vvj-5mfj | CVE-2024-34064 | UNKNOWN | 3.1.4 | The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes |
| jinja2@2.10 | GHSA-q2x7-8rv6-6q7h | CVE-2024-56326 | UNKNOWN | 3.1.5 | An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the c |
| jinja2@2.10 | GHSA-cpwx-vrp4-4pq7 | CVE-2025-27516 | UNKNOWN | 3.1.6 | An oversight in how the Jinja sandboxed environment interacts with the `/attr` filter allows an attacker that controls t |
| pyyaml@5.3 | PYSEC-2020-96 | CVE-2020-1747, CVE-2025-50460 | UNKNOWN | 5.3.1 | A vulnerability was discovered in the PyYAML library in versions before 5.3.1, where it is susceptible to arbitrary code |
| pyyaml@5.3 | PYSEC-2021-142 | CVE-2020-14343 | UNKNOWN | 5.4 | A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code e |
| pyyaml@5.3 | GHSA-6757-jp84-gxfx | CVE-2020-1747 | UNKNOWN | 5.3.1 | A vulnerability was discovered in the PyYAML library in versions before 5.3.1, where it is susceptible to arbitrary code |
| requests@2.19.1 | PYSEC-2018-28 | CVE-2018-18074 | UNKNOWN | 2.20.0 | The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-ho |
| requests@2.19.1 | GHSA-j8r2-6x86-q33q | CVE-2023-32681 | UNKNOWN | 2.31.0 | ### Impact |
| requests@2.19.1 | GHSA-9wx4-h78v-vm56 | CVE-2024-35195 | UNKNOWN | 2.32.0 | When using a `requests.Session`, if the first request to a given origin is made with `verify=False`, TLS certificate ver |
| requests@2.19.1 | GHSA-9hjg-9r4m-mvj7 | CVE-2024-47081 | UNKNOWN | 2.32.4 | ### Impact |
| requests@2.19.1 | GHSA-gc5v-m9x4-r6x2 | CVE-2026-25645 | UNKNOWN | 2.33.0 | ### Impact |
| urllib3@1.24.1 | PYSEC-2019-133 | CVE-2019-11324 | UNKNOWN | 1.24.2 | The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is differ |
| urllib3@1.24.1 | PYSEC-2019-132 | CVE-2019-11236 | UNKNOWN | 1.24.3 | In the urllib3 library through 1.24.1 for Python, CRLF injection is possible if the attacker controls the request parame |
| urllib3@1.24.1 | PYSEC-2020-148 | CVE-2020-26137 | UNKNOWN | 1.25.9 | urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserti |
| urllib3@1.24.1 | GHSA-34jh-p97f-mpxf | CVE-2024-37891 | UNKNOWN | 1.26.19, 2.2.2 | When using urllib3's proxy support with `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured  |
| urllib3@1.24.1 | GHSA-v845-jxx5-vc9f | CVE-2023-43804 | UNKNOWN | 1.26.17, 2.0.6 | urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is th |
| urllib3@1.24.1 | GHSA-gwvm-45gx-3cf8 | CVE-2018-25091 | UNKNOWN | 1.24.2 | urllib3 before 1.24.2 does not remove the authorization HTTP header when following a cross-origin redirect (i.e., a redi |
| urllib3@1.24.1 | GHSA-g4mx-q9vg-27p4 | CVE-2023-45803 | UNKNOWN | 1.26.18, 2.0.7 | urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status 303 "See Other" aft |
| urllib3@1.24.1 | GHSA-pq67-6m6q-mj2v | CVE-2025-50181 | UNKNOWN | 2.5.0 | urllib3 handles redirects and retries using the same mechanism, which is controlled by the `Retry` object. The most comm |
| urllib3@1.24.1 | GHSA-gm62-xv2j-4w53 | CVE-2025-66418 | UNKNOWN | 2.6.0 | ## Impact |
| urllib3@1.24.1 | GHSA-2xpw-w6gg-jr37 | CVE-2025-66471 | UNKNOWN | 2.6.0 | ### Impact |
| urllib3@1.24.1 | GHSA-38jv-5279-wg99 | CVE-2026-21441 | UNKNOWN | 2.6.3 | ### Impact |
| urllib3@1.24.1 | GHSA-qccp-gfcp-xxvc | CVE-2026-44431 | UNKNOWN | 2.7.0 | ### Impact |
| urllib3@1.24.1 | GHSA-vxq7-64xx-v4gw | CVE-2026-97689 | UNKNOWN | 2.8.0 | ## Impact |

## Unpinned dependencies

- `flask`
- `gunicorn`
