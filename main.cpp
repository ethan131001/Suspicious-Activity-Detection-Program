#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector> 
#include <set>
#include <map>
#include <ctime>

const int TIME_FRAME = 60*10; // 10 minute window (in seconds) for numerous failed logins being flagged

using namespace std;


// Logs each line of the log file
class LogEntry {
private:
    string date;
    string time;
    string user;
    string action;
    string status;
    string dataTransferred;
    string ipAddress;

    // Utility function to convert date and time strings into time_t
    time_t convertToTimeT(const string& dateTime) const {
        struct tm tm = {};
        stringstream ss(dateTime);
        ss >> get_time(&tm, "%Y-%m-%d %H:%M:%S");
        return mktime(&tm);
    }

public:
    // Constructor for initializing from a line of log data
    LogEntry(const string& line) {
        istringstream stream(line);
        string temp;

        stream >> date >> time;  // Extract date and time

        // No need to call convertToTimeT in the constructor, this will be done by getTimeAsTimeT() later

        stream >> temp >> user; // Skip to "User:" and extract username
        stream >> action;       // Extract action (Login or Data Transfer)

        // Check action type (Login or Data Transfer)
        if (action == "Login:") {
            stream >> status;          // Get the result of the login (e.g., Success or Failed)
            dataTransferred = "N/A";   // No data transferred for login
        } else if (action == "Data") {
            stream >> temp >> dataTransferred; // Extract data transfer amount
            status = "N/A";                    // No login status for data transfer
        }

        stream >> temp >> ipAddress; // Read the IP address
    }

    // Combine date and time and convert to time_t
    time_t getTimeAsTimeT() const {
        string dateTime = date + " " + time;
        return convertToTimeT(dateTime); // We only need to call this once now
    }

    // Getters for the private members
    string getUser() const { return user; }
    string getStatus() const { return status; }
    string getAction() const { return action; }
    string getIp() const { return ipAddress; }
    string getData() const { return dataTransferred; }  // Added missing semicolon
};

// Logs failed logins and data tranfsers, and checks for suspicious acitivity.
class SuspiciousActivity {
private:
    map<string, vector<time_t> > failedLogins;  // Stores failed logins per user
    map<string, vector<pair<time_t, int> > > dataTransfers;  // Stores data transfers per user
    int threshold;

public:
    // Constructor that sets the threshold
    SuspiciousActivity(int threshold) : threshold(threshold) {}

  // Function to check suspicious activity for a specific user
    void checkSuspiciousLogin(const string& user) {
    auto it = failedLogins.find(user);
    if (it != failedLogins.end()) {
        // Step 2: Get the failed logins for the user
        const auto& userFailedLogins = it->second;  // Get the vector of failed logins for the user
        int count = userFailedLogins.size();

        if(count >= threshold) {
            // We have enough failed logins, now check for suspicious activity
            bool suspicious = false;  // Flag to track if suspicious activity is detected

            

            // Loop through each pair of failed logins to check the time difference
            for (int i = 0; i < count; ++i) {
                for (int j = i + 1; j < count; ++j) {
                    // Check if the time difference between two failed logins is within the time frame
                    if (difftime(userFailedLogins[j], userFailedLogins[i]) <= TIME_FRAME) {
                        cout << "Suspicious activity detected for user: " << user << endl;
                        cout << "User " << user << " has multiple failed logins within " 
                             << TIME_FRAME / 60 << " minutes." << endl;
                        suspicious = true;
                        break;  // Exit the inner loop as soon as suspicious activity is found
                    }
                }
                if (suspicious) {
                    break;  // Exit the outer loop as well if suspicious activity has been detected
                }
            }

            // If no suspicious activity was found after all comparisons
            if (!suspicious) {
                cout << "User " << user << " has " << count << " failed login attempts, which exceeds the threshold of " 
                     << threshold << " attempts." << endl;
                cout << "However, the failed login attempts are not within " 
                     << TIME_FRAME / 60 << " minutes of each other, so suspicious activity cannot be confirmed." << endl;
            }
        } else {
            // Not enough failed logins to trigger threshold
            cout << "User " << user << " has " << count << " failed login attempts, which is less than the threshold of " 
                 << threshold << " attempts. No suspicious activity detected." << endl;
        }
    } else {
        // No failed logins for the user

        cout << "No suspicious activity detected for User " << user << ". No failed logins found." << endl;
    }
}

    // Function to check suspicious activity for a specific user
    void checkSuspiciousTransfer(const string& user) {
        auto it = dataTransfers.find(user);
    if (it != dataTransfers.end()) {
        // Get the data transfer for the user
        const auto& userDataTransfers= it->second;  
        int count = userDataTransfers.size();

        

        if(count >= 2) { // Need at least 2 data transfers
            // We have enough data transfers, now check for suspicious activity
            bool suspicious = false;  // Flag to track if suspicious activity is detected
            

            // Loop through each pair of transfers to check the time difference
            for (int i = 0; i < count; ++i) {
                  // Skip transfers smaller than 1GB, no need to compare them
                if (userDataTransfers[i].second < 1024) {
                    continue;
                }

                for (int j = i + 1; j < count; ++j) {
                      // Skip transfers smaller than 1GB, no need to compare them
                    if (userDataTransfers[j].second < 1024) {
                    continue;
                    }

                    // Check if the time difference between two transfers and their sizes
                    if(difftime(userDataTransfers[j].first, userDataTransfers[i].first) <= TIME_FRAME){
                        cout << "Suspicious activity detected for user: " << user << endl;
                        cout << "User " << user << " has multiple transfers larger than 1GB within " 
                             << TIME_FRAME / 60 << " minutes." << endl;
                        suspicious = true;
                        break;  // Exit the inner loop as soon as suspicious activity is found
                    }
                }
                if (suspicious) {
                    break;  // Exit the outer loop as well if suspicious activity has been detected
                }
            }

            // If no suspicious activity was found after all comparisons
            if (!suspicious) {
                cout << "User " << user << " has " << count 
                << " data transfers larger than 1GB, but no suspicious activity detected." << endl;
            }
        } else {
            // Not enough transfers to trigger threshold
            cout << "User " << user << " has " << count << " data trasnfers, which is less than the threshold of " 
                 << threshold << " data transfer. No suspicious activity detected." << endl;
        }
    } else {
        // No data transfers for the user

        cout << "No suspicious activity detected for User " << user << ". No transfers found" << endl;
    }
    }

     // Method to log a failed login for a user
    void logFailedLogin(const string& user, time_t loginTime) {
        failedLogins[user].push_back(loginTime);
    }

    // Method to log a data transfer for a user
    void logDataTransfers(const string& user, time_t transferTime, int dataSize) {
        dataTransfers[user].push_back(make_pair(transferTime, dataSize));
    }

    void printDataTransfers() const {
        // Loop through failed logins and print them in a human-readable format
        for (const auto& entry : dataTransfers) {
            const string& user = entry.first;
            const vector<pair<time_t, int> >& transfers = entry.second;

            cout << "User: " << user << " had the following data transfers:" << endl;

            // Loop through each failed login time for the user
            for (const auto& t : transfers) {
                // Convert the time_t to local time
                struct tm* localTime = localtime(&t.first);
                
                // Buffer to hold the formatted time
                char timeBuffer[20];

                // Format the time into the desired string format (YYYY-MM-DD HH:MM:SS)
                strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", localTime);

                // Output the formatted time
                cout << "Transfer of size "<< t.second << "MB at: " << timeBuffer << endl;
                }

            cout << endl;  // Just to separate different user
            }
        }

    void printFailedLogins() const {
        // Loop through failed logins and print them in a human-readable format
        for (const auto& entry : failedLogins) {
            const string& user = entry.first;
            const vector<time_t>& times = entry.second;

            cout << "User: " << user << " had the following failed login attempts:" << endl;

            // Loop through each failed login time for the user
            for (time_t t : times) {
                // Convert the time_t to local time
                struct tm* localTime = localtime(&t);
                
                // Buffer to hold the formatted time
                char timeBuffer[20];

                // Format the time into the desired string format (YYYY-MM-DD HH:MM:SS)
                strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", localTime);

                // Output the formatted time
                cout << "Failed at: " << timeBuffer << endl;
                }

            cout << endl;  // Just to separate different user
            }
        }
};



int main() {
    ifstream LogFile("Log.txt");
    string line;
    vector<LogEntry> logs;
    set<string> uniqueUsers;
    int threshold = 3;  // Threshold for flagging suspicious login activity

    SuspiciousActivity suspiciousActivity(threshold);  // Create an instance of SuspiciousActivity



    if (LogFile.is_open()) {
        while (getline(LogFile, line)) {
            LogEntry logEntry(line);  // Create a LogEntry object for each line in the log
            logs.push_back(logEntry); // Store logEntry object in the vector

            // Store unique users
            uniqueUsers.insert(logEntry.getUser());

            // If login failed, log the failed login time
            if (logEntry.getAction() == "Login:" && logEntry.getStatus() == "Failed") {
                suspiciousActivity.logFailedLogin(logEntry.getUser(), logEntry.getTimeAsTimeT());
                
            } else if(logEntry.getAction() == "Data") {
                int dataSize = stoi(logEntry.getData());
                suspiciousActivity.logDataTransfers(logEntry.getUser(), logEntry.getTimeAsTimeT(), dataSize);
            }

        }
        LogFile.close();
    } else {
        cout << "Unable to open file" << endl;
    }


    cout << "Login checks: \n";
     for (const auto& itr : uniqueUsers) {
         cout << "\n";
        suspiciousActivity.checkSuspiciousLogin(itr);
       
    }  
   cout << "\nData transfer checks:\n";
     for (const auto& itr : uniqueUsers) {
         cout << "\n";
        suspiciousActivity.checkSuspiciousTransfer(itr);
       
    }  
    
    return 0;
}

