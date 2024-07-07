# Security Incident Response Playbooks

This repository contains security incident response playbooks for various scenarios such as data breaches, DDoS attacks, and ransomware infections. Each playbook includes step-by-step instructions and automation scripts to handle the incidents effectively.

## Overview

<img width="1074" alt="Screenshot 2024-07-08 at 1 20 12 AM" src="https://github.com/MenakaGodakanda/Security-Incident-Response-Playbooks/assets/156875412/51749e87-5085-4155-b2ca-00922567faae">

### Key Components

- **Playbook Directory**: Contains individual playbooks for different incident types (`Data Breach`, `DDoS Attack`, `Ransomware`).
- **Steps for Incident Response**: Detailed steps for incident response (`playbook.md`).
- **Scripts for Detection and Mitigation**: Python scripts for detection and mitigation (`detect_breach.py`, `mitigate_ddos.py`, `remove_ransomware.py`).
- **Ansible Playbook for Automation**: Ansible playbooks for automation (`ansible_playbook.yml`).

## Playbooks

- [Data Breach]()
- [DDoS Attack]()
- [Ransomware]()

## Installation

- **Git**: Git is required to clone the repository from GitHub.
   ```bash
   sudo apt install git -y
   ```

- **Python 3 and pip**: Python 3 and pip are necessary to run the Python scripts and manage dependencies.
   ```bash
   sudo apt install python3 python3-pip -y
   ```

- **virtualenv**: `virtualenv` is used to create isolated Python environments for the project.
   ```bash
   sudo apt install virtualenv -y
   ```

- **Ansible**: Ansible is required for the automation tasks described in the playbooks.
   ```bash
   sudo apt install ansible -y
   ```

## Usage

### 1. Clone the Repository:
   Navigate to the directory where you want to store your project and clone your GitHub repository.
   ```bash
   git clone https://github.com/MenakaGodakanda/Security-Incident-Response-Playbooks.git
   cd Security-Incident-Response-Playbooks
   ```

### 2. Create a Virtual Environment:
   It's good practice to work within a virtual environment to isolate your project's dependencies. This command creates a virtual environment named `venv` using Python 3.
   ```bash
   virtualenv venv --python=python3
   ```

### 3. Activate the Virtual Environment
   Activate the virtual environment to start using it. You should see (venv) prefixed to your command prompt, indicating that the virtual environment is active.
   ```bash
   source venv/bin/activate
   ```

### 4. Navigate to the desired playbook directory
   For example, navigate for data breach:
   ```bash
   cd playbooks/data_breach
   ```

### 5. Follow the instructions in `playbook.md`.
   - Run the Provided Scripts:
   ```bash
   python scripts/detect_breach.py
   ```

   - Use Ansible for Automation:
   ```bash
   ansible-playbook automation/ansible_playbook.yml
   ```

### 6. Deactivate the Virtual Environment (Optional)
   When you're done working on your project, you can deactivate the virtual environment.
   ```bash
   deactivate
   ```

## Project Directory Structure
```
Security-Incident-Response-Playbooks/
├── README.md
└── playbooks/
    ├── data_breach/
    │   ├── automation/
    │   │   ├── inventory
    │   │   ├── ansible_playbook.yml
    │   ├── scripts/
    │   │   ├── detect_breach.py
    │   │   └── utils.py
    │   └── examples/
    │       ├── sample_log.txt
    │       └── example_output.txt
    ├── ddos_attack/
    │   ├── automation/
    │   │   ├── inventory
    │   │   ├── ansible_playbook.yml
    │   ├── scripts/
    │   │   ├── mitigate_ddos.py
    │   │   └── utils.py
    │   └── examples/
    │       ├── sample_log.txt
    │       └── example_output.txt
    └── ransomware/
        ├── automation/
        │   ├── inventory
        │   ├── ansible_playbook.yml
        ├── scripts/
        │   ├── remove_ransomware.py
        │   └── utils.py
        └── examples/
            ├── sample_log.txt
            └── example_output.txt
```

## License

This project is licensed under the MIT License.
