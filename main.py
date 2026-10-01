from pathlib import Path
import logging
import csv
from analyzer import Analyzer
from report import Report

PATH_TO_LOGS = Path(__file__).parent /"security_logs.csv"
PATH_SAVED_REPORT = Path(__file__).parent /"saved_report.json"

def main():
    logs = []

    if not PATH_TO_LOGS.exists():
        logging.error(f"Error: The file {PATH_TO_LOGS} does not exist.")
        return logs
    
    with open(PATH_TO_LOGS, "r", encoding="utf-8") as file:
        return list(csv.DictReader(file))

def get_output_choice():
    print("Would you like to display the report in the console or save it to a file?    ")
    while True:
        user_choice = input("Enter 'console' or 'file': ").strip().lower()
        if user_choice in ['console', 'file']:
            return user_choice
        else:
            print("Invalid input. Please enter 'console' or 'file'.")

if __name__ == "__main__":
    logs = main()
    analyzer = Analyzer(logs)
    failed_count = analyzer.count_failed_logins()
    verdict_ip_list = analyzer.detect_threats()
    report = Report(verdict_ip_list)
    final_report = report.generate_report(failed_count)
    choice = get_output_choice()
    if choice == "console":
        report.display_report(final_report)
    elif choice == "file":
        report.save_report(final_report, PATH_SAVED_REPORT)
        print(f"Report saved to {PATH_SAVED_REPORT}")
