# ANGB — Automated Non-Executable Binary Guard

ANGB is a security-oriented CLI tool designed to safely analyze files without executing them, combining multiple static analysis techniques and heuristics to detect suspicious or malicious characteristics.

It is especially useful for analyzing:
- Downloaded videos, documents, binaries, or archives
- Files from untrusted sources
- Media files that should not contain executable content

ANGB runs fully isolated inside Docker, ensuring your host system is never exposed.

------------------------------------------------------------
FEATURES
------------------------------------------------------------

- No execution of analyzed files (pure static analysis)
- Antivirus scan using ClamAV
- Binary inspection using strings
- Embedded content detection using binwalk
- Media validation using ffmpeg and mediainfo
- File type verification using the file utility
- Heuristic-based risk scoring and diagnosis
- Works from any directory via a global CLI command
- Fully reproducible installation and removal

------------------------------------------------------------
ARCHITECTURE
------------------------------------------------------------

ANGB consists of:

1. A Python analysis engine (main.py)
2. A Docker container providing all security tools
3. A thin host-side CLI wrapper (angb)
4. Install and uninstall scripts

The analyzed file is mounted read-only into the container and is never executed.

------------------------------------------------------------
REQUIREMENTS
------------------------------------------------------------

- Linux
- Docker
- Bash
- sudo access (required for install and uninstall)

------------------------------------------------------------
INSTALLATION
------------------------------------------------------------

From the project root:

1. Grant execution permissions:

   chmod +x install.sh bin/angb uninstall.sh

2. Install ANGB:

   ./install.sh

This will:
- Build the Docker image
- Install the angb command into /usr/local/bin

------------------------------------------------------------
USAGE
------------------------------------------------------------

From any directory:

   angb <file>

Example:

   angb suspicious_video.mp4

ANGB will output:
- File metadata
- Antivirus scan results
- Embedded content analysis
- Heuristic-based security diagnosis

------------------------------------------------------------
WHAT ANGB CHECKS
------------------------------------------------------------

- File type mismatch (extension vs actual content)
- Presence of suspicious strings (shells, URLs, commands)
- Embedded executables or archives
- Unexpected scripts inside media files
- Abnormal metadata
- Antivirus signatures (ClamAV)

------------------------------------------------------------
DIAGNOSTIC LEVELS
------------------------------------------------------------

ANGB reports one of the following classifications:

- SAFE
- LOW RISK
- SUSPICIOUS
- HIGH RISK

The classification is heuristic-based and conservative by design.

------------------------------------------------------------
SECURITY MODEL
------------------------------------------------------------

- Files are never executed
- Docker container runs without network access
- Files are mounted read-only
- No persistent container state
- No data leaves the host

------------------------------------------------------------
TESTING WITH MALICIOUS FILES
------------------------------------------------------------

You can safely test ANGB using:

- The EICAR antivirus test string
- Files with embedded ZIP or ELF headers
- Files containing shell-like strings
- Fake file extensions (e.g., .mp4 that is actually a script)

ANGB detects these patterns without executing the files.

------------------------------------------------------------
UNINSTALLATION
------------------------------------------------------------

To completely remove ANGB from your system:

1. Grant execution permission (if not already done):

   chmod +x uninstall.sh

2. Run the uninstall script:

   ./uninstall.sh

This will:
- Remove the angb CLI command from /usr/local/bin
- Remove the Docker image used by ANGB
- Leave all user files untouched

------------------------------------------------------------
PROJECT STRUCTURE
------------------------------------------------------------

angb/
├── Dockerfile
├── main.py
├── install.sh
├── uninstall.sh
└── bin/
    └── angb

------------------------------------------------------------
DISCLAIMER
------------------------------------------------------------

ANGB is a static analysis tool and does not guarantee detection of all malware.
It should be used as an additional safety layer, not as a replacement for good security practices.

------------------------------------------------------------
LICENSE
------------------------------------------------------------

MIT License
