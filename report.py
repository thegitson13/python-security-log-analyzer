import json 
import logging

class Report:
    def __init__(self, logs):
        self.logs = logs

    def generate_report(self, failed_count):
        report = {}
        total_fail = failed_count
        report["total_failed_logins"] = total_fail
        for ip, log in self.logs.items():
            if log["verdict"] == "NORMAL":
                severity = "LOW"

            elif log["verdict"] == "FAILED_AND_SUCCESSFUL_LOGINS":
                severity = "MEDIUM"

            elif log["verdict"] == "POSSIBLE_BRUTE_FORCE":
                severity = "HIGH"

            report[ip] = {
                "failed_logins": log["failed"],
                "successful_logins": log["success"],
                "verdict": log["verdict"],
                "severity": severity
            }

        return report

    def display_report(self, report):
        print("Security Report:")
        print(f"Total Failed Logins: {report['total_failed_logins']}")
        for ip, log in report.items():
            if ip != "total_failed_logins":
                print(f"\nIP Address: {ip}")
                print(f"Failed Logins: {log['failed_logins']}")
                print(f"Successful Logins: {log['successful_logins']}")
                print(f"Verdict: {log['verdict']}")
                print(f"Severity: {log['severity']}")
        

    def save_report(self, report, filename):
        try:
            with open(filename, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=4)

        except IOError as e:
            logging.error(f"Error saving report to {filename}: {e}")

