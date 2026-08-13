# SOC Log Analyzer & Brute-Force Alerting Tool

A lightweight Python security automation script designed to parse server authentication logs, extract client IP addresses using Regular Expressions (Regex), and alert security analysts when an IP exceeds a brute-force failure threshold.

## Features
- **Log Parsing:** Extracts target IP addresses from raw log files via Regex pattern matching.
- **Threat Detection:** Tracks failed login counts per IP address.
- **Alerting Logic:** Flags potential brute-force attacks exceeding configurable threshold metrics.

## Requirements
- Python 3.x
