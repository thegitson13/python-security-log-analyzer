# Python Security Log Analyzer

A Python-based security log analysis tool that parses authentication logs,
aggregates login activity by IP address, detects potentially suspicious
behavior, assigns severity levels, and generates security reports.

## Features

- CSV security log parsing
- Failed login detection
- Login activity aggregation by IP address
- Potential brute-force detection
- Suspicious login activity detection
- Severity classification
- Console report generation
- JSON report export

## Project Structure

- `main.py` - application entry point and CSV loading
- `analyzer.py` - log analysis and threat detection
- `report.py` - report generation and JSON export
- `security_logs.csv` - sample security dataset

## Usage

Run:

```bash
python3 main.py
