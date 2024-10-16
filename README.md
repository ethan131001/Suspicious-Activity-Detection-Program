# Suspicious Activity Detection Program

This project is a C++ program designed to analyze log files for suspicious user activity, particularly failed login attempts and large data transfers, in order to detect potential insider threats or brute-force attacks.

## Features

- **Login Monitoring**: Detects users with multiple failed login attempts within a defined 10-minute time window.
- **Data Transfer Monitoring**: Identifies users who transfer more than 1GB of data within a short time frame.
- **Real-time Analysis**: Processes log files and identifies suspicious patterns as they occur.
- **Custom Threshold**: The threshold for detecting suspicious login attempts can be customized.
- **Efficient Data Storage**: Uses C++ data structures like maps and vectors to efficiently store and compare user activity.

## How It Works

- **Failed Login Detection**: If a user fails multiple login attempts within a 10-minute window, it is flagged as suspicious. You can set a custom threshold for how many failed attempts trigger the suspicion.
- **Data Transfer Detection**: If a user transfers more than 1GB of data within a 10-minute period, it is flagged as suspicious.

The program reads a log file with the following format:

Date Time User: username Action: Result IP: IP address

## File Structure

- `LogEntry`: Class responsible for parsing and storing individual log entries.
- `SuspiciousActivity`: Class responsible for analyzing user activities and detecting suspicious patterns.
- `main()`: The main function reads a log file, processes the entries, and checks for suspicious activities.

## Usage

### Prerequisites

Make sure you have a C++ compiler installed (e.g., `g++`).

### Compilation

To compile the program, run the following command in your terminal:

g++ -o activity_detector main.cpp

### Running the Program

Ensure the program is in the same directory as your log file, `Log.txt`. The `Log.txt` file should contain user activity logs in the following format:

2023-10-14 12:01:45 User: Alice Login: Failed IP: 192.168.1.1
2023-10-14 12:05:10 User: Alice Data Transfer: 2048 IP: 192.168.1.1

To run the program, use the following command in the terminal:

./activity_detector

The program will analyze the log file and print out suspicious activities based on failed logins or large data transfers. Here's an example output:

### Login checks:

- **Suspicious activity detected for user: Alice**
  - User Alice has multiple failed logins within 10 minutes.

- **User Bob:**
  - 5 failed login attempts, but no suspicious activity detected.

---

### Data transfer checks:

- **Suspicious activity detected for user: Alice**
  - User Alice has multiple transfers larger than 1GB within 10 minutes.

- **User Bob:**
  - No suspicious activity detected. No transfers found.
