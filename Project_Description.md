# Security Incident Response Playbooks - Version 1

The "Security Incident Response Playbooks" project provides a comprehensive, automated, and easy-to-use solution for responding to various cybersecurity incidents. By leveraging Ansible for automation, Python for scripting, and open-source tools for monitoring and protection, the project ensures a robust and effective incident response strategy. The clear documentation and example files make it accessible for users to set up and customize according to their specific needs.

## Features

### 1. Incident Response Playbooks
The project includes detailed playbooks for handling different types of security incidents. Each playbook contains:
- Step-by-Step Instructions: Clear, sequential steps to respond to the incident.
- Automation Scripts: Scripts to automate parts of the response process, reducing response time and minimizing human error.

### 2. Automation with Ansible
Ansible playbooks are used for automating response tasks, ensuring consistent and repeatable actions. Key features include:
- Automated Installation and Configuration: Ensures necessary tools and services are installed and configured correctly.
- Task Automation: Automates tasks like updating virus definitions, blocking IPs, and configuring monitoring.
- Localhost Configuration: Designed to run on the local machine, making it easy to test and develop.

### 3. Python Scripting
Python scripts are utilized to handle specific detection and mitigation tasks:
- Log Analysis: Analyzes logs to detect potential breaches or attacks.
- Alerting: Sends alerts when suspicious activity is detected.
- Blocking IPs: Automatically blocks IPs associated with suspicious activity.

### 4. Detailed Logging and Monitoring
The project includes mechanisms for logging and monitoring activities:
- Auditd Integration: Monitors access to sensitive files and logs changes.
- Log Rotation: Ensures logs are rotated and archived properly to prevent disk space issues and maintain log availability.

### 5. Configurable Thresholds
Thresholds for detecting incidents (e.g., number of failed login attempts, number of connections from a single IP) are configurable, allowing customization based on specific security policies and environments.

### 6. Ease of Use
The project is designed to be easy to use and set up:
- Comprehensive Documentation: README files and comments in the code provide detailed explanations of how to set up and use the project.
- Example Data and Outputs: Sample log files and output examples help users understand how the scripts work and what to expect.

### 7. Open Source Tools
The project relies on open source tools, making it accessible and cost-effective:
- Ansible: For automation.
- Auditd: For monitoring file access.
- ClamAV: For malware detection.
- Iptables: For managing firewall rules.

### 8. Security Best Practices
The playbooks and scripts follow security best practices, ensuring robust and reliable incident response:
- Least Privilege: Scripts and tasks run with the minimum necessary privileges.
- Logging and Auditing: Ensures all actions are logged for accountability and audit purposes.
- Regular Updates: Automated updates for virus definitions and other critical components.

### Example Outputs
#### Data Breach Response
- Installed and configured auditd: Ensures monitoring of sensitive files.
- Set up log rotation: Ensures logs are properly managed.

#### DDoS Attack Response
- Blocked IPs with excessive connections: Automatically adds firewall rules to block malicious IPs.
- Rate limiting: Configures iptables to limit the rate of incoming connections.

#### Ransomware Response
- Installed and updated ClamAV: Ensures the latest malware definitions.
- Scheduled scans: Regularly scans the system for ransomware.

## Data Breach Scripting

### Script to detect data breaches (`playbooks/data_breach/scripts/detect_breach.py`)
#### Import Statements
- `import re`: This imports the `re` module, which provides support for regular expressions in Python. Regular expressions are used for searching, matching, and manipulating strings based on specific patterns.
- `from utils import send_alert`: This imports the `send_alert` function from the `utils` module. This function is likely responsible for sending an alert when a security breach is detected in the logs.

#### Constants
- `LOG_FILE`: This constant defines the path to the log file (`sample_log.txt`) that contains the server logs to be analyzed.
- `OUTPUT_FILE`: This constant defines the path to the output file (`example_output.txt`) where the alerts will be written after detection.

#### Function: `detect_breach`
- `def detect_breach():`: This defines a function named `detect_breach` that will be used to detect security breaches in the log file.
- `with open(LOG_FILE, 'r') as file:`: This opens the log file in read mode. The `with` statement ensures that the file is properly closed after its suite finishes, even if an exception is raised.
- `logs = file.readlines()`: This reads all the lines from the log file and stores them as a list of strings in the variable `logs`. Each string in the list corresponds to a single line in the log file.
  - `alerts = []`: This initializes an empty list called `alerts` to store any alerts that are generated.
  - `for log in logs:`: This starts a loop that iterates over each line (log entry) in the `logs` list.
  - `if re.search(r'Failed password for invalid user', log):`: This uses the `re.search` function to check if the current log entry contains the string "Failed password for invalid user". The `r` before the string indicates a raw string, which means backslashes are treated literally.
  - `alert = send_alert(log)`: If the regular expression search is successful (i.e., the log entry matches the pattern), the `send_alert` function is called with the log entry as its argument. This function likely processes the log entry and generates an alert.
  - `alerts.append(alert)`: The generated alert is appended to the `alerts` list.
    - `with open(OUTPUT_FILE, 'w') as file:`: This opens the output file in write mode. Again, the `with` statement ensures that the file is properly closed after its suite finishes.
    - `for alert in alerts:`: This starts a loop that iterates over each alert in the alerts list.
    - `file.write(f"{alert}\n")`: This writes each alert to the output file, followed by a newline character. The `f` before the string indicates an f-string, which allows embedding expressions inside string literals using curly braces `{}`.

#### Main Block
- `if __name__ == "__main__":`: This checks if the script is being run as the main program. If it is, the code inside this block is executed.
- `detect_breach()`: This calls the `detect_breach` function to start the process of detecting breaches in the log file.

### Utility functions used by the script (`playbooks/data_breach/scripts/utils.py`)
#### Function: send_alert
- Function Definition:
  - `def send_alert(message):`
    - This line defines a function named `send_alert` that takes a single parameter called `message`.
- Creating an Alert Message:
  - `alert = f"ALERT: {message}"`
    - This line creates a formatted string that combines the word "ALERT:" with the content of the `message` parameter.
    - The `f` before the string indicates an f-string, which allows embedding expressions inside string literals using curly braces `{}`.
    - For example, if `message` is `"Failed password attempt from 192.168.1.100"`, the `alert` variable will be assigned the value `"ALERT: Failed password attempt from 192.168.1.100"`.
- Printing the Alert:
  - `print(alert)`
    - This line prints the `alert` string to the console. This is useful for debugging or logging purposes, allowing you to see the alert message immediately in the terminal or log file.
- Returning the Alert:
  - `return alert`
    - This line returns the `alert` string. By returning the alert, this function can be used in other parts of the program to capture and possibly further process the alert message.

### Ansible Playbook: Data Breach Response (`playbooks/data_breach/automation/ansible_playbook.yml`)
#### Playbook Header
- `---`: Indicates the beginning of the YAML document.
- `- name: Data Breach Response Playbook`: The name of the playbook, describing its purpose.
- `hosts: localhost`: Specifies that the tasks in this playbook should be executed on the local machine.
- `become: true`: Indicates that tasks should be run with elevated privileges (sudo).
- `become_user: root`: Specifies that the tasks should be run as the root user. This can be replaced with a different sudo user if needed.

#### Task 1: Ensure auditd is installed
- `- name: Ensure auditd is installed`: The name of the task, describing its purpose.
- `apt`: The Ansible module used to manage packages on Debian-based systems.
  - `name: auditd`: The name of the package to be installed.
  - `state: present`: Ensures that the `auditd` package is installed. If it is not already installed, it will be installed.
- `become: yes`: Ensures this task runs with elevated privileges.

#### Task 2: Start and enable auditd service
- `- name: Start and enable auditd service`: The name of the task, describing its purpose.
- `service`: The Ansible module used to manage services.
  - `name: auditd`: The name of the service to be managed.
  - `state: started`: Ensures that the `auditd` service is running.
  - `enabled: yes`: Ensures that the `auditd` service is enabled to start at boot.
- `become: yes`: Ensures this task runs with elevated privileges.

#### Task 3: Monitor access to sensitive files
- `- name: Monitor access to sensitive files`: The name of the task, describing its purpose.
- `command`: The Ansible module used to run a command on the target host.
  - `auditctl -w /etc/passwd -p wa -k passwd_changes`: The command to be run. This sets up auditing on the `/etc/passwd` file to log write (`w`) and attribute change (`a`) operations. The `-k - - passwd_changes` option adds a key to identify this specific audit rule.
- `become: yes`: Ensures this task runs with elevated privileges.

#### Task 4: Ensure logrotate is installed
- `- name: Ensure logrotate is installed`: The name of the task, describing its purpose.
- `apt`: The Ansible module used to manage packages on Debian-based systems.
  - `name: logrotate`: The name of the package to be installed.
  - `state: present`: Ensures that the `logrotate` package is installed. If it is not already installed, it will be installed.
- `become: yes`: Ensures this task runs with elevated privileges.

#### Task 5: Set up log rotation for audit logs
- `- name: Set up log rotation for audit logs`: The name of the task, describing its purpose.
- `copy`: The Ansible module used to copy files to the target host.
  - `content`: The content of the file to be created on the target host.
    - `/var/log/audit/audit.log`: Specifies the log file to be rotated.
    - `missingok`: If the log file is missing, proceed to the next one without error.
    - `notifempty`: Do not rotate the log file if it is empty.
    - `compress`: Compress the rotated log files.
    - `delaycompress`: Delay compression of the rotated log files until the next rotation.
    - `daily`: Rotate the log files daily.
    - `rotate 7`: Keep 7 days' worth of rotated log files.
    - `postrotate`: Specifies a command to run after the log file is rotated.
      - `/etc/init.d/auditd reload > /dev/null`: Reload the `auditd` service to apply changes.
    - `endscript`: Ends the `postrotate` script section.
  - `dest: /etc/logrotate.d/audit`: The destination path on the target host where the file will be created.
- `become: yes`: Ensures this task runs with elevated privileges.

### Ansible Inventory File (`playbooks/data_breach/automation/Inventory`)
Ansible uses inventory files to define which machines to manage and how to connect to them. The inventory file can be in various formats (INI, YAML, or dynamic inventory scripts), but the INI format is commonly used for static inventories. This snippet is in the INI format.

#### `[servers]`
- This line defines a group of hosts named servers.
- Groups are a way to organize and categorize hosts for easier management and targeted execution of playbooks and tasks.
- You can have multiple groups in an inventory file, and a host can belong to multiple groups.

#### `localhost ansible_connection=local`
- This line defines a host entry under the `servers` group.
- `localhost`
  - `localhost` is the hostname or IP address of the machine.
  - `localhost` refers to the local machine where Ansible is being run. It's a special hostname recognized by most systems to refer to itself.
- `ansible_connection=local`
  - This is a variable that specifies the connection type to be used when connecting to the host.
  - `ansible_connection` is a connection variable in Ansible.
  - The value `local` means that Ansible should run tasks locally on the machine where Ansible is being executed, rather than connecting over SSH or another remote connection method.

##### Putting It All Together
- This inventory file snippet does the following:
- Defines a group named `servers`:
  - This is a logical grouping of hosts, which in this case contains only one host: `localhost`.
- Defines a host `localhost` under the `servers` group:
  - Specifies that this host should be managed using the local connection type (`ansible_connection=local`), meaning Ansible will execute tasks directly on the local machine rather than connecting to a remote host.

## DDoS Attack Scripting
