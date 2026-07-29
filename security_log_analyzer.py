from collections import Counter

LOG_FILE = "security.log"

failed_attempts = Counter()

with open(LOG_FILE, "r") as file:
    for line in file:
        parts = line.strip().split()

        if len(parts) >= 4 and parts[2] == "FAILED_LOGIN":
            ip_address = parts[3]
            failed_attempts[ip_address] += 1

print("=== Security Log Analyzer ===")
print("\nFailed login attempts by IP:")

if not failed_attempts:
    print("No failed login attempts found.")
else:
    for ip, count in failed_attempts.items():
        print(f"{ip} -> {count} failed attempt(s)")

print("\nSuspicious IP addresses (3+ failed attempts):")

suspicious_found = False

for ip, count in failed_attempts.items():
    if count >= 3:
        print(f"⚠️ {ip} -> {count} failed attempts")
        suspicious_found = True

if not suspicious_found:
    print("No suspicious IP addresses found.")