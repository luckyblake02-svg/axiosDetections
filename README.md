# axiosDetections

This repository contains three Python scripts that work together to detect risky Azure AD users, enrich events with AbuseIPDB data, alert responders via email, and optionally automate response when Azure sends “user at risk” notifications.

> Note: Replace placeholder values (tenant IDs, app IDs, emails, secret IDs, paths, and environment variable names) with values appropriate for your environment.

***

## Overview

- **Script 1 – Risky Axios Console Detector**  
  Interactive, console-based tool that queries Microsoft Graph Identity Protection for risky users, enriches their detections and sign-ins, and highlights sign-ins using the `axios` user agent.
- **Script 2 – Risky Axios Email Reporter**  
  Non-interactive script that collects similar data, builds a consolidated text report, and emails it to a defined distribution list.
- **Script 3 – Risky Axios Outlook Watcher**  
  Windows/Outlook watcher that polls the inbox for specific Azure “user at risk” notifications and, when found, invokes a headless axios detection script.

---

## Prerequisites

### Common

- Python 3.8+  
- Network access to:
  - Microsoft Graph (`https://graph.microsoft.com`)  
  - AbuseIPDB API (`https://api.abuseipdb.com`)  
  - Your Delinea Secret Server instance  

- Access to:
  - **Azure AD / Microsoft Graph**
    - App registration with certificate-based authentication
    - Permissions to read Identity Protection data (`riskyUsers`, `riskDetections`) and sign-in logs
    - For Script 2: permission to send mail as the configured sender
  - **Delinea Secret Server**
    - API user with rights to read the secret containing the certificate passphrase
  - **AbuseIPDB**
    - API key for the `check` endpoint

### Script 3 Specific

- Windows host with Outlook installed and configured for the target mailbox  
- `pywin32` installed (for `win32com.client`)  
- The headless axios detection script (`axiosHeadless`) available on the Python path

---

## Setup & Installation

1. **Clone the repository**

```bash
git clone https://github.com/luckyblake02-svg/axiosDetections.git
cd axiosDetections
```

2. **Create and activate a virtual environment (recommended)**

```bash
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows
venv\Scripts\activate
```

3. **Install dependencies**

Typical packages used across the scripts:

- `delinea.secrets.server`
- `azure-identity` (for `CertificateCredential`)
- `msgraph-beta`, `msgraph`, `kiota-abstractions`
- `requests`
- `pywin32` (for Script 3)

4. **Configure environment variables**

Set these environment variables as appropriate:

- Secret Server API user password for Delinea:
  - `env variable` – used in `ssToken()` in Script 1 and Script 2
- AbuseIPDB API key:
  - `env variable` (Script 1)  
  - `abuseAPI` (Script 2)

You can set them in your shell, in a secrets manager, or as part of your host configuration.

***

## Script 1 – Risky Axios Console Detector

### Purpose

Queries Microsoft Graph Identity Protection for risky users updated today, retrieves related risk detections and sign-ins, enriches IP information with AbuseIPDB, and prints results to the console, with special emphasis on sign-ins using the `axios` user agent.

### Key Behavior

- Authenticates to Delinea Secret Server using a password grant to retrieve a certificate passphrase.  
- Uses `CertificateCredential` and the Microsoft Graph beta client to access Identity Protection APIs.  
- Filters `riskyUsers` where:
  - `riskState` is `atRisk`
  - `riskLastUpdatedDateTime` is on or after the current date  
- For each risky user:
  - Shows user principal name, risk level, and risk state
  - In parallel:
    - Fetches Identity Protection risk detections (`risk_detections`)
    - Fetches recent sign-ins (`audit_logs.sign_ins`)  
  - Optionally prints risk detections and AbuseIPDB data for each detection IP:
    - Abuse confidence score
    - Country code
    - ISP
    - Domain
    - Total reports
    - Last reported time  
  - Optionally prints sign-in events:
    - App display name
    - Timestamp
    - User agent
    - Flags any sign-in where `user_agent == 'axios'` with a warning to trigger a phishing playbook

### Configuration Points

Inside the script, update:

- Secret Server:
  - `site` – Secret Server base URL (e.g., `https://secretserver/SecretServer`)
  - `username` – Secret Server API account
  - `secret number` – ID of the secret holding the certificate passphrase
- Azure:
  - `tenant_id` – Azure tenant ID
  - `client_id` – app registration client ID
  - `cert_path` – path to the certificate file

### Running Script 1

```bash
python riskyAxiosInteractive.py
```

You will be prompted whether to display detections and sign-ins for each risky user and will see warnings for `axios` user agent sign-ins.

***

## Script 2 – Risky Axios Email Reporter

### Purpose

Fetches a (small, configurable) set of risky users and their related detections and sign-ins, enriches detection IPs with AbuseIPDB data, builds a plain-text summary, and sends it as an email to a set of recipients using Microsoft Graph.

### Key Behavior

- Uses the same Delinea Secret Server + certificate-based Graph authentication pattern as Script 1.  
- Filters `riskyUsers` with:
  - `riskState` = `atRisk`
  - `riskLastUpdatedDateTime` on or after today
  - `top=1` risky user (configurable)  
- For that user:
  - Collects:
    - UPN
    - Risk level
    - Risk state  
  - Uses `asyncio.gather` to get:
    - Up to `top=3` risk detections
    - Up to `top=3` sign-ins  
  - For each detection:
    - Queries AbuseIPDB for the detection IP and appends the abuse metadata to the message body  
  - For each sign-in:
    - Appends app display name, timestamp, and user agent
    - Appends a warning if `user_agent == 'axios'`  
- Builds a `Message` (Graph `sendMail`) with:
  - Subject: `Risky User Information`
  - Body: the assembled text
  - To: two configured recipients
  - Sender: configured mailbox (`by_user_id('sender email')`)
  - Saves a copy to Sent Items

### Configuration Points

Inside the script, update:

- Secret Server:
  - `site`, `username`, `get_secret(####)` (ID of secret containing certificate passphrase)
- Azure:
  - `tenant_id`, `client_id`, `cert_path`
- Email:
  - Recipient addresses in:
    - `recipient = Recipient(email_address=EmailAddress(address='email1'))`
    - `recipient2 = Recipient(email_address=EmailAddress(address='email2'))`
  - Sender mailbox in:
    - `graph_client.users.by_user_id('sender email')`

You can also adjust the `top` values for risky users, detections, and sign-ins to broaden or reduce the volume of data.

### Running Script 2

```bash
python riskyAxiosEmailReport.py
```

On completion, recipients should receive a consolidated text report summarizing risky user activity and any axios-related warnings.

---

## Script 3 – Risky Axios Outlook Watcher

### Purpose

Runs on a Windows machine with Outlook installed, periodically polling the Inbox for specific Azure “user at risk detected” emails, and triggers a headless axios detection script when such alerts arrive.

### Key Behavior

- Uses `win32com.client` to:
  - Attach to the default Outlook MAPI namespace
  - Open the default Inbox (folder index `6`)  
- On each poll:
  - Iterates unread messages
  - For each unread message:
    - If `Subject == "User at risk detected"` and `SenderName == "azure-noreply@microsoft.com"`, executes the `axiosHeadless` script/module  
- Sleeps for 600 seconds (10 minutes) between polls and runs indefinitely

### Configuration Points

Inside the script, you may want to:

- Adjust the matching criteria:
  - Subject: `"User at risk detected"`
  - Sender: `"azure-noreply@microsoft.com"`  

- Optionally mark processed messages as read or move them to a specific folder to avoid reprocessing on subsequent loops.

### Running Script 3

From a Windows machine with Outlook configured:

```bash
python riskyAxiosOutlookWatcher.py
```

Leave it running in the background (or configure it as a scheduled task/service) to keep watching for new Azure risk emails.

***

## Operational Flow Example

A typical end‑to‑end use of these scripts might look like:

1. **Detection & Reporting**
   - Script 1 is used interactively by an analyst to investigate risky users and immediately see axios-based sign-ins.
   - Script 2 runs on a schedule (e.g., via cron or Task Scheduler) to email summarized daily reports to a security distribution list.

2. **Automation**
   - Azure sends a “User at risk detected” email to a monitored mailbox.
   - Script 3, running on a Windows host, detects the new email and triggers the `axiosHeadless` script.
   - The headless script performs automated investigation or remediation steps (for example, disabling accounts, sending notifications, or updating tickets).

Adjust the scripts and configuration to match your organization’s environment, naming standards, and response playbooks.
