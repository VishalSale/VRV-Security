import csv
from collections import defaultdict

# Constants
LOG_FILE = 'sample.log'  # Path to the log file
CSV_FILE = 'log_analysis_results.csv'  # Path to the output CSV file

# Dictionary to count failed login attempts per IP
count_failed_login_attempts = defaultdict(int)

def parse_log_file(file_path):
    ip_requests = defaultdict(int)  # Dictionary to store IP request counts
    endpoint_requests = defaultdict(int)  # Dictionary to store endpoint request counts

    # Read log file line by line
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()  # Split the line into parts
            ip = parts[0]  # Extract IP address
            endpoint = parts[6]  # Extract endpoint
            status_code = parts[8]  # Extract HTTP status code

            ip_requests[ip] += 1  # Increment request count for the IP
            endpoint_requests[endpoint] += 1  # Increment request count for the endpoint

            # If the status code is 401 (failed login attempt)
            if status_code == '401':
                count_failed_login_attempts[ip] += 1  # Increment failed login count for the IP

    return ip_requests, endpoint_requests

# Display Requests per IP, Most Accessed Endpoint & Suspicious Activity in terminal
def display_results(ip_requests, most_accessed_endpoint, file_path):
    #Display the analysis results in the terminal.
    # Display requests per IP
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda item: item[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    # Display most accessed endpoint
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # Display suspicious activity
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in count_failed_login_attempts.items():
        print(f"{ip:<20} {count}")

# Save Requests per IP, Most Accessed Endpoint & Suspicious Activity in a CSV file
def save_to_csv(ip_requests, most_accessed_endpoint, file_path):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # Write requests per IP
        writer.writerow(["Requests per IP:"])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_requests.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])
        
        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint:"])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Write suspicious activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity:'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in count_failed_login_attempts.items():
            writer.writerow([ip, count])

def main():
    """
    Main function to parse log file, analyze data, and save/display results.
    """
    ip_requests, endpoint_requests = parse_log_file(LOG_FILE)
    
    # Identify the most accessed endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda item: item[1])
    
    # Display results in terminal
    display_results(ip_requests, most_accessed_endpoint, LOG_FILE)
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, CSV_FILE)

# Calling main function
main()
