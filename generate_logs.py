import random
import time
from datetime import datetime, timedelta

def generate_log_file(filename, num_lines):
    print(f"Generating {num_lines} lines of fake logs to {filename}...")
    start_time = time.time()
    
    # 20 distinct IP addresses, but some are "malicious" and appear way more often
    ips = [f"192.168.1.{i}" for i in range(1, 21)]
    malicious_ips = ["192.168.1.7", "192.168.1.13", "192.168.1.19"]
    
    # Weights for random choice to heavily favor malicious IPs
    weights = [10 if ip in malicious_ips else 1 for ip in ips]
    
    methods = ["GET", "POST", "PUT", "DELETE"]
    endpoints = ["/index.html", "/login", "/api/data", "/images/logo.png", "/admin"]
    statuses = [200, 201, 301, 400, 401, 403, 404, 500, 502]
    
    # Weights for status codes (lots of 404s and 500s for our analyzer to find)
    status_weights = [50, 10, 5, 5, 5, 5, 20, 15, 5]

    base_time = datetime.now() - timedelta(days=30)
    
    with open(filename, 'w') as f:
        for i in range(num_lines):
            ip = random.choices(ips, weights=weights)[0]
            
            # If it's a malicious IP, guarantee it's causing an error (4xx or 5xx)
            if ip in malicious_ips:
                status = random.choice([401, 403, 404, 500])
            else:
                status = random.choices(statuses, weights=status_weights)[0]
                
            method = random.choice(methods)
            endpoint = random.choice(endpoints)
            size = random.randint(100, 5000)
            
            # Increment time slightly
            base_time += timedelta(seconds=random.randint(0, 5))
            time_str = base_time.strftime("%d/%b/%Y:%H:%M:%S -0400")
            
            log_line = f'{ip} - - [{time_str}] "{method} {endpoint} HTTP/1.1" {status} {size}\n'
            f.write(log_line)
            
            # Print progress every 500,000 lines
            if (i + 1) % 500000 == 0:
                print(f"Generated {i + 1} lines...")

    end_time = time.time()
    print(f"Done! Created {filename} in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    # Generate 1 million lines (approx 100MB)
    generate_log_file("server.log", 1000000)
