from utils import block_ip

LOG_FILE = 'examples/sample_log.txt'
OUTPUT_FILE = 'examples/example_output.txt'

def detect_ddos():
    ip_counter = {}
    with open(LOG_FILE, 'r') as file:
        logs = file.readlines()

    for log in logs:
        ip = log.split()[0]
        if ip not in ip_counter:
            ip_counter[ip] = 0
        ip_counter[ip] += 1

    blocked_ips = []
    for ip, count in ip_counter.items():
        if count > 10:
            blocked_ip = block_ip(ip)
            blocked_ips.append(blocked_ip)
    
    with open(OUTPUT_FILE, 'w') as file:
        for blocked_ip in blocked_ips:
            file.write(f"{blocked_ip}\n")

if __name__ == "__main__":
    detect_ddos()
