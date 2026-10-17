\# FileSentinel

\### Automated File Integrity Monitoring and Tampering Detection System



FileSentinel is a Python-based file integrity monitoring application that detects changes in monitored directories by comparing file hashes against a saved baseline. It provides a Streamlit dashboard for monitoring file activity and reviewing audit events.



\## Features



\- \*\*SHA-256 hashing:\*\* Generates cryptographic hashes to identify file-content changes.

\- \*\*Baseline management:\*\* Saves a reference state for monitored directories.

\- \*\*Change detection:\*\* Identifies added, modified, and deleted files.

\- \*\*Continuous monitoring:\*\* Uses Watchdog to observe filesystem activity.

\- \*\*Audit logging:\*\* Stores monitoring events in an SQLite database.

\- \*\*Interactive dashboard:\*\* Displays monitoring information, event statistics, and audit history.

\- \*\*Integrity verification:\*\* Compares current file states with previously saved baseline information.

\- \*\*Automated tests:\*\* Includes pytest tests for scanning, integrity checks, database operations, monitoring, and watcher behavior.



\## Technology Stack



| Component | Technology |

|---|---|

| Programming language | Python |

| User interface | Streamlit |

| File hashing | SHA-256 (`hashlib`) |

| Filesystem monitoring | Watchdog |

| Database | SQLite |

| Data visualization | Altair, Pandas |

| Testing | pytest |



\## Project Structure



```text

FileSentinel/

├── app.py

├── requirements.txt

├── data/

│   └── filesentinel.db       # Generated locally

├── src/

│   └── filesentinel/

│       ├── scanner.py

│       ├── integrity.py

│       ├── database.py

│       ├── monitoring.py

│       └── watcher.py

├── tests/

│   ├── test\_database.py

│   ├── test\_integrity.py

│   ├── test\_monitoring.py

│   ├── test\_scanner.py

│   └── test\_watcher.py

└── .gitignore

```



\## Prerequisites



\- Python 3.12 or a compatible Python version

\- pip

\- Windows, Linux, or macOS

\- Git (optional, for cloning the repository)



\## Installation



\### 1. Clone the repository



```bash

git clone https://github.com/Diksha121310/TNS-Cyber.git

cd TNS-Cyber

```



Make sure you are inside the directory containing `app.py` and `requirements.txt`.



\### 2. Create a virtual environment



```bash

python -m venv .venv

```



Activate it on Windows PowerShell:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



On Linux or macOS:



```bash

source .venv/bin/activate

```



\### 3. Install dependencies



```bash

python -m pip install -r requirements.txt

```



\## Running the Application



From the project root directory, run:



```bash

streamlit run app.py

```



Streamlit will display the local address for opening the dashboard in your browser.



\## Running Tests



Execute the automated test suite with:



```bash

python -m pytest -v

```



The current test suite contains 25 tests covering database operations, file scanning, integrity change detection, monitoring, and watcher behavior.



\## How It Works



1\. \*\*Select a directory:\*\* Register the directory that should be monitored.

2\. \*\*Create a baseline:\*\* Scan the directory and calculate SHA-256 hashes for its files.

3\. \*\*Monitor the directory:\*\* Perform scans or use continuous filesystem monitoring.

4\. \*\*Compare file states:\*\* Compare the current file information with the saved baseline.

5\. \*\*Record events:\*\* Store detected file changes in the SQLite audit database.

6\. \*\*Review results:\*\* Use the dashboard and audit history to inspect recorded events.



\### Change Types



\- \*\*Added:\*\* A file exists in the current scan but was not present in the reference state.

\- \*\*Modified:\*\* A file's recorded content hash differs from the reference state.

\- \*\*Deleted:\*\* A file existed in the reference state but is absent from the current scan.



\## Security Considerations and Limitations



\- SHA-256 hashes help identify file-content changes; they do not establish that a file is malicious.

\- FileSentinel is a file integrity monitoring tool, not a complete antivirus or endpoint detection and response (EDR) system.

\- Monitoring reliability depends on filesystem permissions, successful scans, and the availability of the application.

\- A baseline should be protected against unauthorized modification. If an attacker can alter both monitored files and the baseline database, the integrity guarantees are weakened.

\- Continuous monitoring and periodic scans have different operational characteristics; verify the application is running and monitoring the intended directories.

\- FileSentinel does not guarantee detection of every security incident.



\## Future Enhancements



\- Email or desktop notifications for critical file changes.

\- Configurable monitoring policies and severity levels.

\- Exportable audit reports.

\- Authentication and role-based access control.

\- Protected baseline storage and stronger audit-log integrity.

\- Additional integration and reliability tests.



\## License



No license has been specified yet. Add a license before permitting others to reuse or redistribute this project.



\---



\*\*FileSentinel\*\* — Monitor file integrity, detect unexpected changes, and maintain an audit trail.

