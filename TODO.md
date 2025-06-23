# 📌 TODO - Future Improvements Roadmap

This document outlines the planned improvements for the project. Tasks are grouped by theme to help organize development workflow.

---

## 📚 1. Documentation Improvements
- [ ] Include screenshots of Grafana dashboards
- [ ] Add sample logs (e.g. quarantined message)
- [ ] Create a short demo GIF/video showing the full detection process
- [ ] Document how to simulate clean and malicious emails

---

## 🧪 2. Testing & Validation
- [ ] Add a test script or manual test instructions (`scripts/test.sh` or `docs/manual_test.md`)
- [ ] Include sample emails with safe and malicious attachments
- [ ] Validate full end-to-end flow (scanner → quarantine/log → Grafana alert)

---

## 🔐 3. SMTP Security Enhancements
- [ ] Support `STARTTLS` or SSL for SMTP connections
- [ ] Suggest `fail2ban` or IP blocking for repeated bad senders
- [ ] Filter suspicious email headers (e.g., spoofed `From:` or `Return-Path`)

---

## 🚨 4. Alerting & Notification System
- [ ] Add webhook support for alerting (Discord/Slack/Telegram)
- [ ] Optional: Email notification to admin when quarantine happens

---

## 🗂️ 5. Code Refactoring & Folder Structure
- [ ] Separate config/constants into their own files

---

## 🧬 6. Detection Enrichment
- [ ] Integrate VirusTotal API for scanning attachments or hashes
- [ ] Add IP reputation lookup (e.g., AbuseIPDB)

---

## 💻 7. Lightweight Web Interface (Optional)
- [ ] Create a minimal web UI (Flask/FastAPI) to:
- Display quarantined emails
- Download or inspect attachments
- Manually release or delete emails

---

## 📈 8. PDF Report Export
- [ ] Add PDF generation with daily/weekly summary:
- Total received emails
- YARA/Sigma detections
- Quarantine events
- Alerts triggered

---

