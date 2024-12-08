import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Parse log file and extract data
def parse_log(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Match IP addresses
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            ip_requests[ip] += 1

            # Match endpoints
            endpoint_match = re.search(r'\"(?:GET|POST) ([^ ]+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Detect failed logins
            if "401" in line or "Invalid credentials" in line:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

# Write results to CSV
def write_to_csv(file_name, ip_requests, most_accessed_endpoint, failed_logins):
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP requests
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

# Main function
def main():
    log_file = "sample.log"
    ip_requests, endpoint_requests, failed_logins = parse_log(log_file)
    
    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")
    
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")
    
    # Write results to CSV
    write_to_csv("log_analysis_results.csv", ip_requests, most_accessed_endpoint, failed_logins)

if __name__ == "__main__":
    main()
