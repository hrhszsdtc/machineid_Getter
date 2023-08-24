#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <algorithm>
#include <regex>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32")
#endif

#ifdef __linux__
#include <unistd.h>
#endif

std::string exec(const std::string &cmd)
{
    std::array<char, 128> buffer;
    std::string result;
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return result;

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(
            NULL,
            const_cast<char *>(cmd.c_str()),
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi))
    {
        CloseHandle(hWrite);

        DWORD bytesRead;
        while (ReadFile(hRead, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, NULL))
        {
            result.append(buffer.data(), bytesRead);
        }
        CloseHandle(hRead);

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return result;
    }
    else
    {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return result;
    }
#else
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe)
        return result;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr)
    {
        result.append(buffer.data());
    }
    return result;
#endif
}

std::string read(const std::string &path)
{
    std::ifstream f(path);
    if (f.is_open())
    {
        std::string content((std::istreambuf_iterator<char>(f)), (std::istreambuf_iterator<char>()));
        return content;
    }
    return "";
}

std::string reg(const std::string &registry, const std::string &key)
{
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD type, cbData = 1024;
        std::string value(cbData, '\0');
        if (RegQueryValueExA(hKey, key.c_str(), NULL, &type, reinterpret_cast<BYTE *>(&value[0]), &cbData) == ERROR_SUCCESS)
        {
            value.resize(cbData);
            value.shrink_to_fit();
            RegCloseKey(hKey);
            return value;
        }
        RegCloseKey(hKey);
    }
    return "";
#else
    return "";
#endif
}

std::string id(bool winregistry = true)
{
#ifdef __APPLE__
    return exec("ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'");
#elif defined(_WIN32)
    if (winregistry)
        return reg("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid");
    else
        return exec("powershell.exe -ExecutionPolicy bypass -command (Get-CimInstance -Class Win32_ComputerSystemProduct^).UUID");
#elif defined(__linux__)
    std::string id = read("/var/lib/dbus/machine-id");
    if (id.empty())
        id = read("/etc/machine-id");
    if (id.empty())
    {
        std::string cgroup = read("/proc/self/cgroup");
        if (cgroup.find("docker") != std::string::npos)
            id = exec("head -1 /proc/self/cgroup | cut -d/ -f3");
    }
    if (id.empty())
    {
        std::string mountinfo = read("/proc/self/mountinfo");
        if (mountinfo.find("docker") != std::string::npos)
            id = exec("grep 'systemd' /proc/self/mountinfo | cut -d/ -f3");
    }
    if (id.empty() && std::regex_search(std::string(uname().release), std::regex(".*microsoft.*")))
    {
        id = exec("powershell.exe -ExecutionPolicy bypass -command \"(Get-CimInstance -Class Win32_ComputerSystemProduct^).UUID\"");
    }
    return id;
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
    std::string id = read("/etc/hostid");
    if (id.empty())
        id = exec("kenv -q smbios.system.uuid");
    return id;
#else
    return "";
#endif
}

int main()
{
    std::cout << id() << std::endl;
    return 0;
}

