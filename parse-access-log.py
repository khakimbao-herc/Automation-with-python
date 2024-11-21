import re
from collections import defaultdict

def extract_ip_addresses(log_files):
    ip_counts = defaultdict(int)  # Use a defaultdict to count occurrences
    
    # Regular expression for matching IP addresses
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for log_file in log_files:
        with open(log_file, 'r') as file:
            for line in file:
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    ip_counts[ip] += 1  # Increment the count for the IP address

    return ip_counts

def filter_ips(ip_counts, min_access_count=3):
    """Exclude IPs that accessed the server less than min_access_count times."""
    return {ip: count for ip, count in ip_counts.items() if count >= min_access_count}

def parse_for_webshells(log_files, webshells):
    attempted_webshell_access = defaultdict(list)  # Store attempted access with the corresponding IP addresses

    for log_file in log_files:
        with open(log_file, 'r') as file:
            for line in file:
                for webshell in webshells:
                    if webshell in line:
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            attempted_webshell_access[webshell].append(ip)  # Append the IP to the webshell entry

    return attempted_webshell_access

def parse_for_scanning_attempts(log_files, threshold=5):
    scan_attempts = defaultdict(int)
    access_times = defaultdict(list)

    for log_file in log_files:
        with open(log_file, 'r') as file:
            for line in file:
                timestamp = line.split()[3][1:]  # Extract timestamp
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    access_times[ip].append(timestamp)  # Record the access time for the IP

    # Analyze recorded access times to detect scanning patterns
    for ip, times in access_times.items():
        if len(times) >= threshold:
            scan_attempts[ip] = len(times)  # Count scanning attempts based on threshold

    return scan_attempts

def filter_upload_attempts(log_files):
    """Filter and return IPs that attempted to upload files."""
    upload_attempts = defaultdict(list)  # Store attempted uploads with corresponding IPs
    upload_pattern = re.compile(r'POST\s+[^\s]*(\.php|\.jsp|\.asp|\.exe|\.pl|\.py|\.txt|\.zip|\.tar|\.gz)')  # Adjust file types as needed

    for log_file in log_files:
        with open(log_file, 'r') as file:
            for line in file:
                if upload_pattern.search(line):  # Check if the line indicates an upload attempt
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        upload_attempts[ip].append(line.strip())  # Append the whole line for context

    return upload_attempts

def read_successful_upload_attempts(log_files):
    """Read and return successful upload attempts."""
    successful_uploads = defaultdict(list)  # Store successful uploads with corresponding IPs
    upload_success_pattern = re.compile(r'POST\s+[^\s]*(\.php|\.jsp|\.asp|\.exe|\.pl|\.py|\.txt|\.zip|\.tar|\.gz) HTTP/1\.1" 200|201')  # Regex for successful uploads (200 or 201 status)

    for log_file in log_files:
        with open(log_file, 'r') as file:
            for line in file:
                if upload_success_pattern.search(line):  # Check for successful upload
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        successful_uploads[ip].append(line.strip())  # Append details of successful upload

    return successful_uploads

def write_report_to_file(report_file, ip_access_counts, webshell_access_counts, scan_attempts, upload_attempts, successful_uploads):
    with open(report_file, 'w') as file:
        file.write("IP Addresses and Their Access Counts (sorted):\n")
        print("IP Addresses and Their Access Counts (sorted):")
        for ip, count in sorted(ip_access_counts.items(), key=lambda x: x[1], reverse=True):
            output_line = f"{ip}: {count} access(es)"
            print(output_line)
            file.write(output_line + '\n')

        print("\nAttempted Access to Webshells (sorted):")
        file.write("\nAttempted Access to Webshells (sorted):\n")
        for webshell, ips in webshell_access_counts.items():
            unique_ips = set(ips)
            output_line = f"{webshell}: {len(unique_ips)} access(es) from IPs: {', '.join(unique_ips)}"
            print(output_line)
            file.write(output_line + '\n')

        print("\nPossible Scanning Attempts (sorted):")
        file.write("\nPossible Scanning Attempts (sorted):\n")
        for ip, count in sorted(scan_attempts.items(), key=lambda x: x[1], reverse=True):
            output_line = f"{ip}: {count} potential scanning attempt(s)"
            print(output_line)
            file.write(output_line + '\n')

        print("\nUpload Attempts (sorted):")
        file.write("\nUpload Attempts (sorted):\n")
        for ip, attempts in upload_attempts.items():
            output_line = f"{ip}: {len(attempts)} upload attempt(s) - Details: {', '.join(attempts)}"
            print(output_line)
            file.write(output_line + '\n')

        print("\nSuccessful Upload Attempts (sorted):")
        file.write("\nSuccessful Upload Attempts (sorted):\n")
        for ip, attempts in successful_uploads.items():
            output_line = f"{ip}: {len(attempts)} successful upload(s) - Details: {', '.join(attempts)}"
            print(output_line)
            file.write(output_line + '\n')

# Specify the paths to your access log files
log_file_paths = [
    './path/file/here1',
    './path/file/here2',
    './path/file/here3',
    './path/file/here4',
    './path/file/here5'
]
report_file_path = 'access_report.txt'  # Specify the desired report file name

# Updated list of known webshell file names
known_webshells = [
    'webshell.php',
    'shell.php',
    'b374k.php',
    'p0wny-shell.php',
    'r57.php',
    'simple-backdoor.php',
    'php-reverse-shell.php',
    'c99.php',
    'r57shell.php',
    'w3d.php',
    'W3D_Shell.php',
    'weevely.php',
    'Ajax_PHP_Command_Shell.php',
    'simple-backdoor.php',
    'Antichat_Shell.php',
    'PhpSpy.php',
    'php-reverse-shell.php',
    'TinyShell.php',
    'bash.php',
    'c99madshell.php',
    'tinywebshell.php',
    'bastard_shell.php',
    'evil.php',
    'php-backdoor.php',
    'hack.php',
    'hackerweb.php',
    'simpleshell.php',
    'wso.php',
    'webshell.php',
    'w3t.php',
    'l33t_shell.php',
    'phpshell.php',
    'secupress.php',
    'network.php',
    'asimov.php',
    'shellbot.php'
]

# Extract IP addresses and their access counts across multiple files
ip_access_counts = extract_ip_addresses(log_file_paths)

# Filter IP addresses to exclude those with less than 3 accesses
filtered_ip_access_counts = filter_ips(ip_access_counts, min_access_count=3)

# Parse for webshell attempts and record IP addresses that accessed each web shell
webshell_access_counts = parse_for_webshells(log_file_paths, known_webshells)

# Parse for scanning attempts
scan_attempts = parse_for_scanning_attempts(log_file_paths, threshold=5)

# Parse for upload attempts
upload_attempts = filter_upload_attempts(log_file_paths)

# Parse for successful upload attempts
successful_uploads = read_successful_upload_attempts(log_file_paths)

# Write the report to a .txt file and print to terminal
write_report_to_file(report_file_path, filtered_ip_access_counts, webshell_access_counts, scan_attempts, upload_attempts, successful_uploads)

print(f"\nReport has been written to '{report_file_path}' successfully.")
