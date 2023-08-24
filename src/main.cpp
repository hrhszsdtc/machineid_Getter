#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#endif
using namespace std;

string __exec__(const string& cmd) {
    char buffer[128];
    string result = "";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

string __read__(const string& path) {
    ifstream file(path);
    if (file.is_open()) {
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
        return content;
    } else {
        return "";
    }
}

#ifdef _WIN32
string __reg__(const string& registry, const string& key) {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, registry.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        throw runtime_error("RegOpenKeyEx() failed!");
    DWORD dwType, dwSize;
    if (RegQueryValueEx(hKey, key.c_str(), NULL, &dwType, NULL, &dwSize) != ERROR_SUCCESS)
        throw runtime_error("RegQueryValueEx() failed!");
    char* value = new char[dwSize];
    if (RegQueryValueEx(hKey, key.c_str(), NULL, &dwType, (LPBYTE)value, &dwSize) != ERROR_SUCCESS)
        throw runtime_error("RegQueryValueEx() failed!");
    RegCloseKey(hKey);
    string result(value);
    delete[] value;
    return result;
}
#endif

string id(bool winregistry = true) {
#ifdef _WIN32
    string platform = "win32";
#else
    string platform = __exec__("uname -s");
#endif
    string id = "";
    if (platform == "Darwin") {
        id = __exec__(
            "ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'"
        );
    } else if (platform == "win32" || platform == "cygwin" || platform == "msys") {
        if (winregistry) {
            id = __reg__(
                "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid"
            );
        } else {
            id = __exec__(
                "powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"
            );
        }
        if (id.empty()) {
            id = __exec__("wmic csproduct get uuid").substr(39);
        }
    } else if (platform.find("Linux") != string::npos) {
        id = __read__("/var/lib/dbus/machine-id");
        if (id.empty()) {
            id = __read__("/etc/machine-id");
        }
        if (id.empty()) {
            string cgroup = __read__("/proc/self/cgroup");
            if (!cgroup.empty()) {
                if (cgroup.find("docker") != string::npos) {
                    id = __exec__("head -1 /proc/self/cgroup | cut -d/ -f3");
                }
            }
        }
        if (id.empty()) {
            string mountinfo = __read__("/proc/self/mountinfo");
            if (!mountinfo.empty()) {
                if (mountinfo.find("docker") != string::npos) {
                    id = __exec__("grep 'systemd' /proc/self/mountinfo | cut -d/ -f3");
                }
            }
        }
        if (id.empty()) {
            if (__exec__("uname -r").find("microsoft") != string::npos) { // wsl
                id = __exec__(
                    "powershell.exe -ExecutionPolicy bypass -command '(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID'"
                );
            }
        }
    } else if (platform.find("OpenBSD") != string::npos || platform.find("FreeBSD") != string::npos) {
        id = __read__("/etc/hostid");
        if (id.empty()) {
            id = __exec__("kenv -q smbios.system.uuid");
        }
    }

    if (id.empty()) {
        throw runtime_error("failed to obtain id on platform " + platform);
    }

    return id;
}
int main(){
    cout << id() << endl;
}
