
class Analyzer:
    def __init__(self, data):
        self.data = data

    def count_failed_logins(self):
        count = 0

        for log in self.data:
            if log["event_type"].strip() == "failed_login":
                count += 1

        return count

    def detect_threats(self):
        ip_holder = {}

        for log in self.data:
            ip = log["src_ip"].strip()
            action = log["event_type"].strip()

            if ip not in ip_holder:
                ip_holder[ip] = {
                    "success": 0,
                    "failed": 0,
                    "verdict": "UNKNOWN"
                }

            if action == "failed_login":
                ip_holder[ip]["failed"] += 1

            elif action == "successful_login":
                ip_holder[ip]["success"] += 1

        for ip, info in ip_holder.items():

            if info["failed"] > 5:
                info["verdict"] = "POSSIBLE_BRUTE_FORCE"

            elif info["failed"] > 0 and info["success"] > 0:
                info["verdict"] = "FAILED_AND_SUCCESSFUL_LOGINS"

            else:
                info["verdict"] = "NORMAL"

        return ip_holder
    


    
         