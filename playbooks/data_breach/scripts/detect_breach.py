import re
from utils import send_alert

LOG_FILE = 'examples/sample_log.txt'
OUTPUT_FILE = 'examples/example_output.txt'

def detect_breach():
    with open(LOG_FILE, 'r') as file:
        logs = file.readlines()
    
    alerts = []
    for log in logs:
        if re.search(r'Failed password for invalid user', log):
            alert = send_alert(log)
            alerts.append(alert)
    
    with open(OUTPUT_FILE, 'w') as file:
        for alert in alerts:
            file.write(f"{alert}\n")

if __name__ == "__main__":
    detect_breach()
