Description:

This project is a multithreaded log analysis system that processes large server log files and identifies IP addresses generating high numbers of HTTP error responses (4xx and 5xx). It uses parallel processing to improve performance and produces a ranked list of potentially malicious IPs. The results are exported as a JSON file and visualized through a modern web-based dashboard.

The system is designed using C++ for high-performance backend processing, Python for test log generation, and HTML/CSS/JavaScript for frontend visualization.

Features:

The major design decisions were focused on performance, scalability, and separation of concerns between backend processing and frontend visualization.

Multithreaded processing:
The log file is divided into chunks based on CPU cores, allowing parallel processing using Windows threads (CreateThread) to significantly improve performance on large datasets.
Efficient log parsing:
Each thread independently parses its portion of the file and extracts IP addresses and HTTP status codes, ensuring minimal contention.
Thread-safe aggregation:
A CRITICAL_SECTION lock is used only during the final merge step to prevent race conditions while keeping synchronization overhead low.
Local aggregation per thread:
Each thread maintains a local hash map (unordered_map) before merging, reducing global locking and improving scalability.
Dynamic workload distribution:
File size is divided into equal chunks using streampos, allowing the system to scale with system hardware.
JSON output for interoperability:
Results are written to results.json, enabling easy integration with the frontend dashboard.
Interactive dashboard visualization:
A web UI displays the top malicious IPs using animated bars, providing a clear and intuitive view of the results.
Test data generation:
A Python script generates realistic log files with controlled malicious IP behavior to simulate real-world conditions.
Separation of concerns:
Backend handles computation, while frontend handles visualization, making the system modular and easier to extend.
