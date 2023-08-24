#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>
#include <regex>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/mount.h>
using namespace std;

string exec(string cmd)
{
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
        return "ERROR";
    }
    char buffer[128];
    string result = "";
    while (!feof(pipe))
    {
        if (fgets(buffer, 128, pipe) != NULL)
        {
            result += buffer;
        }
    }
    pclose(pipe);
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
    return result;
}

string read_file(string path)
{
    ifstream file(path);
    if (!file.is_open())
    {
        return "";
    }
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    return content;
}

string reg_read(string key)
{
    char *cmd = new char[key.length() + 120];
    snprintf(cmd, key.length() + 120, "reg query \"%s\" /v MachineGuid 2>nul | findstr MachineGuid", key.c_str());
    string output = exec(cmd);
    if (output.substr(0, 12) == "MachineGuid")
    {
        output = output.substr(29);
        return output;
    }
    return "";
}

string id(bool winregistry = true)
{
    struct utsname buf;
    uname(&buf);

    if (strcmp(buf.sysname, "Darwin") == 0)
    {
        string cmd = "ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'";
        return exec(cmd);
    }
    else if (strcmp(buf.sysname, "Linux") == 0)
    {
        string u_id = read_file("/var/lib/dbus/machine-id");
        if (u_id.empty())
        {
            u_id = read_file("/etc/machine-id");
        }
        if (u_id.empty())
        {
            string cgroup = read_file("/proc/self/cgroup");
            if (cgroup.find("docker") != string::npos)
            {
                regex pattern("[0-9,a-z]{64}");
                smatch match;
                regex_search(cgroup, match, pattern);
                u_id = match.str(0);
            }
        }
        if (u_id.empty())
        {
            string mountinfo = read_file("/proc/self/mountinfo");
            if (mountinfo.find("docker") != string::npos)
            {
                regex pattern(".+systemd.+");
                smatch match;
                regex_search(mountinfo, match, pattern);
                string path = match.str(0);
                path.erase(remove(path.begin(), path.end(), '\n'), path.end());
                vector<string> paths;
                stringstream ss(path);
                string token;
                while (getline(ss, token, '/'))
                {
                    paths.push_back(token);
                }
                u_id = paths.back();
            }
        }
        if (u_id.empty() && strstr(buf.release, "microsoft"))
        {
            string cmd = "powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID";
            return exec(cmd);
        }
        return u_id;
    }
    else if (strcmp(buf.sysname, "FreeBSD") == 0 || strcmp(buf.sysname, "OpenBSD") == 0)
    {
        string u_id = read_file("/etc/hostid");
        if (u_id.empty())
        {
            string cmd = "kenv -q smbios.system.uuid";
            return exec(cmd);
        }
        return u_id;
    }
    else if (strcmp(buf.sysname, "Windows") == 0)
    {
        if (winregistry)
        {
            return reg_read("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography");
        }
        else
        {
            string cmd = "powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID";
            string output = exec(cmd);
            if (output.empty())
            {
                cmd = "wmic csproduct get uuid";
                output = exec(cmd);
                if (!output.empty())
                {
                    output = output.substr(4);
                }
            }
            return output;
        }
    }
    else
    {
        throw "Unsupported platform";
    }
}

int main()
{
    cout << id() << endl;
    return 0;
}

