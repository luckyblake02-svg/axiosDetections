***

# Risk Insight Scanner

A Python asyncio-based utility that integrates Delinea Secret Server, Microsoft Graph Beta, and AbuseIPDB to identify risky users, fetch their risk detections and sign-in events, and optionally retrieve additional context about IP addresses.

***

## Features

- Retrieves and uses a Secret Server secret via a Password Grant flow.
- Authenticates to Microsoft Graph Beta using a certificate credential.
- Queries risky users and their associated risk detections and sign-in events.
- Optional per-user risk event enrichment by querying AbuseIPDB for IP addresses.
- Interactive prompts to selectively view risk detections and sign-ins.
- Runs asynchronously for efficient data retrieval.

***

## Requirements

- Python 3.8+ (async features used)
- Dependencies (install via pip):
  - asyncio (standard)
  - requests
  - delinea-secrets
  - msgraph-beta
  - azure-identity
  - kiota-abstractions
- Environment variables:
  - env variable storing the Secret Server password (name as used in code)
  - env variable storing AbuseIPDB API key (name as used in code)

- External services:
  - Delinea Secret Server (accessible at the site URL)
  - Microsoft Graph (with appropriate permissions)
  - AbuseIPDB (for IP reputation data)

Note: The script contains placeholder values (e.g., site, tenant_id, client_id, cert_path, etc.) that you must replace with your actual environment configuration.

***

## Setup

1. Create a Python virtual environment (optional but recommended):
   - python -m venv venv
   - source venv/bin/activate (Linux/macOS) or venv\Scripts\activate (Windows)

2. Install dependencies:
   - pip install requests delinea-secrets msgraph-beta azure-identity kiota-abstractions

3. Configure secrets and credentials:
   - Secret Server password: set an environment variable (the code reads it via os.environ with your chosen name).
   - AbuseIPDB API key: set an environment variable named as in the code (env variable placeholder).

4. Update script placeholders with real values:
   - Secret Server site URL (site)
   - Secret number or retrieval method (currently secret = ss_client.get_secret(number); ensure you pass the correct secret number)
   - Azure/Tenant details:
     - tenant_id
     - client_id
     - cert_path
   - Graph scopes (if needed)
   - Any other literal placeholders (tenant id, app id, path to certificate, etc.)

5. Ensure your environment variables are accessible to the script, for example:
   - export YOUR_SECRET_PASSWORD="your-secret-password" (on Unix)
   - export ABUSEIPDB_API_KEY="your-abuseipdb-key"

***

## How to Run

- Simply run the script:
  - python script_name.py

- The script executes as a console application:
  - It authenticates to Secret Server and Graph.
  - Fetches risky users for today.
  - For each risky user, it fetches risk detections and sign-ins in parallel.
  - Prompts to display risk detections and sign-ins.
  - If users opt to see detections, it queries AbuseIPDB for each IP and prints a summary.
  - If sign-ins are requested, it prints sign-in details and flags known bad user agents (e.g., Axios).

***

## Important Notes

- Security:
  - The script uses secrets from Secret Server and a certificate-based Graph authentication flow. Treat all credentials as highly sensitive.
  - Avoid logging sensitive data in production environments. The current script prints several fields for debugging; consider redacting PII or implementing a secure logging strategy.
  - Ensure proper access controls and least-privilege permissions for the service principals and Secrets.

- Error handling:
  - The main function has a broad try/except to print errors and dump a traceback. In a production setting, you’d want structured error handling and possibly retry logic for transient failures.

- Customization:
  - The filter strings for risky users and events are built as Graph beta query parameters. Adjust the filters to reflect your organization’s risk criteria and data retention.
  - The IP checks rely on AbuseIPDB’s API; you may wish to add rate limiting or alternative IP intelligence sources.

- Extensibility:
  - The script uses asyncio.gather to parallelize detections and sign-in lookups. It can be extended to include additional data sources or to persist results to a file or database.

---

***
