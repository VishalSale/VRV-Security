# Assignment: Log File Analysis Script

## Overview

This assignment involves creating a Python script to analyze a log file, extract valuable insights, and present the results in both the terminal and a CSV file. The script is designed to process the log data to determine:
1. The number of requests made by each IP address.
2. The most frequently accessed endpoint.
3. Suspicious activity, specifically failed login attempts (HTTP status code 401) from each IP address.

## Objectives

1. **Parse a log file** to extract necessary information such as IP addresses, endpoints, and status codes.
2. **Count the number of requests** made by each IP address.
3. **Identify the most frequently accessed endpoint** in the log file.
4. **Detect suspicious activity** by counting failed login attempts from each IP address.
5. **Display the results in the terminal** for quick reference.
6. **Save the results to a CSV file** for record-keeping and further analysis.

## Evaluation Criteria

1. **Functionality**: The script should correctly parse the log file and extract required data.
2. **Efficiency**: The script should handle large log files efficiently.
3. **Readability**: The code should be well-organized, properly commented, and follow Python best practices.
4. **Output Format**: The terminal output and CSV file should be clear, accurate, and well-structured.

## Script Explanation

The provided Python script achieves the objectives through the following steps:

### 1. Import Required Libraries

```python
import csv
from collections import defaultdict
```

### 2. Define Constants

```python
LOG_FILE = 'sample.log'  # Path to the log file
CSV_FILE = 'log_analysis_results.csv'  # Path to the output CSV file
```

### 3. Initialize Data Structures

```python
count_failed_login_attempts = defaultdict(int)
```

### 4. Function to Parse Log File

The `parse_log_file` function reads the log file line by line, extracts the IP address, endpoint, and status code, and updates the request counts for each IP and endpoint. It also counts failed login attempts (HTTP status code 401).

```python
def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            ip = parts[0]
            endpoint = parts[6]
            status_code = parts[8]

            ip_requests[ip] += 1
            endpoint_requests[endpoint] += 1

            if status_code == '401':
                count_failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests
```

### 5. Function to Display Results in Terminal

The `display_results` function prints the analysis results, including requests per IP, the most accessed endpoint, and detected suspicious activity.

```python
def display_results(ip_requests, most_accessed_endpoint, file_path):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda item: item[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in count_failed_login_attempts.items():
        print(f"{ip:<20} {count}")
```

### 6. Function to Save Results to CSV

The `save_to_csv` function writes the analysis results to a CSV file, including requests per IP, the most accessed endpoint, and detected suspicious activity.

```python
def save_to_csv(ip_requests, most_accessed_endpoint, file_path):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        writer.writerow(["Requests per IP:"])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_requests.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint:"])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        writer.writerow([])
        writer.writerow(['Suspicious Activity:'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in count_failed_login_attempts.items():
            writer.writerow([ip, count])
```

### 7. Main Function

The `main` function orchestrates the entire process by calling the parsing function, identifying the most accessed endpoint, and calling the display and save functions.

```python
def main():
    ip_requests, endpoint_requests = parse_log_file(LOG_FILE)
    
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda item: item[1])
    
    display_results(ip_requests, most_accessed_endpoint, LOG_FILE)
    
    save_to_csv(ip_requests, most_accessed_endpoint, CSV_FILE)

if __name__ == "__main__":
    main()
```

## Conclusion

This assignment requires developing a Python script to analyze log files effectively. By completing this task, you will demonstrate your ability to handle file input/output, use regular expressions, and manage data with dictionaries. Additionally, presenting the results both in the terminal and as a CSV file showcases your ability to create user-friendly and informative output formats.
