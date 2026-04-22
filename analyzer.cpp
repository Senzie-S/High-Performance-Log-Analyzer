#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <windows.h>

using namespace std;

unordered_map<string, int> globalIpCounts;
CRITICAL_SECTION globalMutex;

struct ThreadData {
    string filename;
    streampos startPos;
    streampos endPos;
};

// Helper function to extract IP and HTTP Status Code from a log line
void parseLine(const string& line, unordered_map<string, int>& localIpCounts) {
    // Basic parsing: Find first space for IP
    size_t ipEnd = line.find(' ');
    if (ipEnd == string::npos) return;
    
    string ip = line.substr(0, ipEnd);
    
    size_t requestEnd = line.find("\" ");
    if (requestEnd == string::npos) return;
    
    size_t statusStart = requestEnd + 2;
    size_t statusEnd = line.find(' ', statusStart);
    if (statusEnd == string::npos) return;

    string statusStr = line.substr(statusStart, statusEnd - statusStart);
    
    try {
        int status = stoi(statusStr);
        if (status >= 400) {
            localIpCounts[ip]++;
        }
    } catch (...) {
    }
}

// Worker function for each thread.
DWORD WINAPI processChunk(LPVOID lpParam) {
    ThreadData* data = (ThreadData*)lpParam;
    string filename = data->filename;
    streampos startPos = data->startPos;
    streampos endPos = data->endPos;

    ifstream file(filename, ios::binary);
    if (!file.is_open()) return 0;

    unordered_map<string, int> localIpCounts;

    file.seekg(startPos);
    string line;

    if (startPos != 0) {
        getline(file, line); 
    }

    while (file.tellg() < endPos && getline(file, line)) {
        parseLine(line, localIpCounts);
    }
    
    if (file.tellg() >= endPos || file.eof()) {
         if (!line.empty()) {
             parseLine(line, localIpCounts);
         }
    }
    
    EnterCriticalSection(&globalMutex);
    for (const auto& pair : localIpCounts) {
        globalIpCounts[pair.first] += pair.second; // Safely add to the global map
    }
    LeaveCriticalSection(&globalMutex); // Unlock it so the next thread can use it

    return 0;
}

bool sortByVal(const pair<string, int>& a, const pair<string, int>& b) {
    return a.second > b.second;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <logfile.log>" << endl;
        return 1;
    }

    string filename = argv[1];
    ifstream file(filename, ios::binary | ios::ate); // Open at end to get size
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return 1;
    }

    streampos fileSize = file.tellg();
    file.close();

    // Initialize global mutex for Windows
    InitializeCriticalSection(&globalMutex);

    // Determine how many parallel workers to spawn by checking your CPU cores
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    unsigned int numThreads = sysinfo.dwNumberOfProcessors;
    if (numThreads == 0) numThreads = 4; // Fallback to 4 if we can't detect cores
    
    cout << "Log file size: " << fileSize / (1024 * 1024) << " MB" << endl;
    cout << "Starting parsing using " << numThreads << " parallel threads..." << endl;

    auto startTime = chrono::high_resolution_clock::now();

    // Divide the file into equal chunks based on the number of threads
    vector<HANDLE> threads;
    vector<ThreadData*> threadData;
    streampos chunkSize = fileSize / numThreads;

    for (unsigned int i = 0; i < numThreads; i++) {
        streampos startPos = i * chunkSize;
        // If this is the last chunk, make sure it goes all the way to the end of the file
        streampos endPos = (i == numThreads - 1) ? fileSize : (startPos + chunkSize);
        
        // Bundle the arguments to send to the thread
        ThreadData* td = new ThreadData{filename, startPos, endPos};
        threadData.push_back(td);

        // Create the thread, This starts executing `processChunk` immediately in parallel.
        HANDLE hThread = CreateThread(NULL, 0, processChunk, td, 0, NULL);
        threads.push_back(hThread);
    }

    // Wait for all threads to finish
    WaitForMultipleObjects(threads.size(), threads.data(), TRUE, INFINITE);

    for (auto h : threads) CloseHandle(h);
    for (auto td : threadData) delete td;

    auto endTime = chrono::high_resolution_clock::now();
    chrono::duration<double, std::milli> duration = endTime - startTime;

    // Sort and print results
    vector<pair<string, int>> sortedResults(globalIpCounts.begin(), globalIpCounts.end());
    sort(sortedResults.begin(), sortedResults.end(), sortByVal);

    cout << "\n--- Parsing Complete in " << duration.count() << " ms ---" << endl;
    cout << "\n TOP 10 MALICIOUS IPs (Generated 4xx/5xx Errors) " << endl;
    
    int limit = min(10, (int)sortedResults.size());
    for (int i = 0; i < limit; i++) {
        cout << i + 1 << ". " << sortedResults[i].first 
             << " - " << sortedResults[i].second << " errors" << endl;
    }

    // Write to results.json
    ofstream outFile("results.json");
    if (outFile.is_open()) {
        outFile << "[\n";
        for (int i = 0; i < limit; i++) {
            outFile << "  {\"ip\": \"" << sortedResults[i].first << "\", \"errors\": " << sortedResults[i].second << "}";
            if (i < limit - 1) outFile << ",";
            outFile << "\n";
        }
        outFile << "]\n";
        outFile.close();
        cout << "\nResults saved to results.json for the dashboard!" << endl;
    }

    DeleteCriticalSection(&globalMutex);
    return 0;
}
