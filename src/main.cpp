#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
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
    char buffer[128];
    string result = "";
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
        return "ERROR";
    }

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
    string content = "";
    ifstream file(path);
    if (file.is_open())
    {
        content = string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
    }

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

string get_machine_id()
{
    string machine_id = "";

    struct utsname buf;
    uname(&buf);

    if (strcmp(buf.sysname, "Darwin") == 0)
    {
        machine_id = exec("ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'");
    }
    else if (strcmp(buf.sysname, "Linux") == 0)
    {
        machine_id = read_file("/var/lib/dbus/machine-id");
        if (machine_id.empty())
        {
            machine_id = read_file("/etc/machine-id");
        }
        if (machine_id.empty())
        {
            string cgroup = read_file("/proc/self/cgroup");
            if (cgroup.find("docker") != string::npos)
            {
                regex pattern("[0-9,a-z]{64}");
                smatch match;
                regex_search(cgroup, match, pattern);
                machine_id = match.str(0);
            }
        }
        if (machine_id.empty())
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
                machine_id = paths.back();
            }
        }
        if (machine_id.empty() && strstr(buf.release, "microsoft"))
        {
            machine_id = exec("powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID");
            if (machine_id.empty())
            {
                machine_id = exec("wmic csproduct get uuid");
                if (!machine_id.empty())
                {
                    machine_id = machine_id.substr(4);
                }
            }
        }
    }
    else if (strcmp(buf.sysname, "FreeBSD") == 0 || strcmp(buf.sysname, "OpenBSD") == 0)
    {
        machine_id = read_file("/etc/hostid");
        if (machine_id.empty())
        {
            machine_id = exec("kenv -q smbios.system.uuid");
        }
    }
    else if (strcmp(buf.sysname, "Windows") == 0)
    {
        machine_id = reg_read("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography");
        if (machine_id.empty())
        {
            machine_id = exec("powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID");
            if (machine_id.empty())
            {
                machine_id = exec("wmic csproduct get uuid");
                if (!machine_id.empty())
                {
                    machine_id = machine_id.substr(4);
                }
            }
        }
    }
    else
    {
        throw "Unsupported platform";
    }

    return machine_id;
}

int main()
{
    cout << get_machine_id() << endl;
    return 0;
}