import re
from utils import quarantine_file

LOG_FILE = 'examples/sample_log.txt'
OUTPUT_FILE = 'examples/example_output.txt'

def detect_ransomware():
    with open(LOG_FILE, 'r') as file:
        logs = file.readlines()
    
    quarantined_files = []
    for log in logs:
        if re.search(r'FOUND', log):
            file_path = log.split()[0]
            quarantined_file = quarantine_file(file_path)
            quarantined_files.append(quarantined_file)
    
    with open(OUTPUT_FILE, 'w') as file:
        for quarantined_file in quarantined_files:
            file.write(f"{quarantined_file}\n")

if __name__ == "__main__":
    detect_ransomware()
