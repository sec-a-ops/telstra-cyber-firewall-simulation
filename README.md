# Telstra Cyber Firewall Simulation

This is a Python-based firewall simulation designed to block a Tomcat WAR/JSP Remote Code Execution (RCE) attack, developed as part of the **Telstra Cyber Virtual Experience Program on Forage**.

---

## What This Project Demonstrates

- Application-layer traffic inspection (HTTP)
- Identification of malicious payloads in POST requests
- Translation of real-world exploit indicators into defensive rules
- Python scripting for defensive cybersecurity applications
- Understanding how RCE attacks manifest at the network level

---

## Simulated Attack Overview

- **Attack Type:** Remote Code Execution (RCE)
- **Target:** Apache Tomcat (WAR/JSP deployment)
- **Method:** Malicious POST request containing a JSP webshell injection
- **Key Indicators:**
  - `class.module.classLoader`
  - `Runtime().exec`
  - `resources.context.parent.pipeline`
  - JSP injection patterns (`<%`, `%{}`)
  - Suspicious custom headers (`c1`, `c2`, `suffix`)

The attack payload is simulated using the `test_requests.py` script.

---

## Firewall Logic

The firewall server performs the following functions:

- Inspects incoming HTTP request bodies
- URL-decodes payloads before inspection
- Blocks requests that match known malicious signatures
- Blocks suspicious headers commonly associated with exploits
- Returns an **HTTP 403 Forbidden** response for malicious traffic
- Allows benign traffic with an **HTTP 200 OK** response

This setup mimics the functionality of basic signature-based firewalls and Web Application Firewalls (WAF).

---

## How to Run

### Requirements
- Python 3 or higher

### Start the Firewall Server
```bash
python firewall_server.py
```

### Simulate the Attack
```bash
python test_requests.py
```

### Expected Result
All malicious requests should be blocked, resulting in 403 Forbidden responses.
