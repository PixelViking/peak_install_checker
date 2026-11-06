#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")

struct InstalledAppInfo {
    bool found = false;
    std::wstring displayName;
    std::wstring version;
};

struct DriverInfo {
    bool installed = false;
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring driverPath;
    std::wstring version;
    DWORD startType = 0;
};

// ---------------------------------------------------------------------------
// Registry Helpers for Application Query
// ---------------------------------------------------------------------------

bool IsSystemComponent(HKEY hKey) {
    DWORD val = 0;
    DWORD size = sizeof(val);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, L"SystemComponent", nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS) {
        if (type == REG_DWORD && val == 1) {
            return true;
        }
    }
    return false;
}

std::wstring ReadRegString(HKEY hKey, const wchar_t* valueName) {
    WCHAR buf[512] = { 0 };
    DWORD bufSize = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &bufSize) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            return std::wstring(buf);
        }
    }
    return L"";
}

InstalledAppInfo SearchUninstallKey(HKEY root, const std::wstring& subPath, REGSAM accessFlags, const std::wstring& targetExactName) {
    InstalledAppInfo result;
    HKEY hUninstallKey = nullptr;

    if (RegOpenKeyExW(root, subPath.c_str(), 0, KEY_READ | accessFlags, &hUninstallKey) != ERROR_SUCCESS) {
        return result;
    }

    DWORD index = 0;
    WCHAR subKeyName[256];
    DWORD subKeyNameLen = ARRAYSIZE(subKeyName);

    while (RegEnumKeyExW(hUninstallKey, index++, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        subKeyNameLen = ARRAYSIZE(subKeyName);
        HKEY hAppKey = nullptr;

        if (RegOpenKeyExW(hUninstallKey, subKeyName, 0, KEY_READ | accessFlags, &hAppKey) == ERROR_SUCCESS) {
            if (!IsSystemComponent(hAppKey)) {
                std::wstring name = ReadRegString(hAppKey, L"DisplayName");
                if (_wcsicmp(name.c_str(), targetExactName.c_str()) == 0) {
                    result.found = true;
                    result.displayName = name;
                    result.version = ReadRegString(hAppKey, L"DisplayVersion");

                    RegCloseKey(hAppKey);
                    break;
                }
            }
            RegCloseKey(hAppKey);
        }
    }

    RegCloseKey(hUninstallKey);
    return result;
}

InstalledAppInfo FindInstalledApp(const std::wstring& exactAppName) {
    struct Scope {
        HKEY root;
        std::wstring path;
        REGSAM flags;
    };

    std::vector<Scope> scopes = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0 }
    };

    for (const auto& scope : scopes) {
        InstalledAppInfo info = SearchUninstallKey(scope.root, scope.path, scope.flags, exactAppName);
        if (info.found) {
            return info;
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Service Control Manager & Binary Version Helpers for Kernel Drivers
// ---------------------------------------------------------------------------

std::wstring GetBinaryFileVersion(const std::wstring& filePath) {
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) return L"Unavailable";

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, data.data())) {
        return L"Unavailable";
    }

    VS_FIXEDFILEINFO* fInfo = nullptr;
    UINT len = 0;
    if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<LPVOID*>(&fInfo), &len) && len > 0) {
        return std::to_wstring(HIWORD(fInfo->dwFileVersionMS)) + L"." +
            std::to_wstring(LOWORD(fInfo->dwFileVersionMS)) + L"." +
            std::to_wstring(HIWORD(fInfo->dwFileVersionLS)) + L"." +
            std::to_wstring(LOWORD(fInfo->dwFileVersionLS));
    }
    return L"Unavailable";
}

DriverInfo QueryDriverService(const std::wstring& serviceName) {
    DriverInfo info;
    info.serviceName = serviceName;

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return info;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_QUERY_CONFIG);
    if (hService) {
        info.installed = true;

        DWORD bytesNeeded = 0;
        QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<BYTE> buffer(bytesNeeded);
            LPQUERY_SERVICE_CONFIGW pConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());

            if (QueryServiceConfigW(hService, pConfig, bytesNeeded, &bytesNeeded)) {
                info.displayName = pConfig->lpDisplayName ? pConfig->lpDisplayName : L"";
                info.startType = pConfig->dwStartType;

                std::wstring rawPath = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"";

                if (rawPath.find(L"\\SystemRoot\\") == 0) {
                    WCHAR winDir[MAX_PATH];
                    GetWindowsDirectoryW(winDir, MAX_PATH);
                    rawPath.replace(0, 11, winDir);
                }
                else if (rawPath.find(L"system32\\") == 0) {
                    WCHAR winDir[MAX_PATH];
                    GetWindowsDirectoryW(winDir, MAX_PATH);
                    rawPath = std::wstring(winDir) + L"\\" + rawPath;
                }

                info.driverPath = rawPath;
                info.version = GetBinaryFileVersion(rawPath);
            }
        }
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
    return info;
}

const wchar_t* StartTypeToString(DWORD startType) {
    switch (startType) {
    case 1:  return L"System Start (1)";
    case 2:  return L"Auto Start (2)";
    case 3:  return L"Demand Start (3)";
    case 4:  return L"Disabled (4)";
    default: return L"Unknown";
    }
}

// ---------------------------------------------------------------------------
// Main Execution
// ---------------------------------------------------------------------------

int main() {
    std::wcout << L"=========================================\n";
    std::wcout << L"       IDS Peak Installation Report      \n";
    std::wcout << L"=========================================\n\n";

    // 1. Check Application / SDK
    std::wcout << L"[1] Application / Suite\n";
    InstalledAppInfo app = FindInstalledApp(L"IDS peak");
    if (app.found) {
        std::wcout << L"    Status  : Installed\n";
        std::wcout << L"    Name    : " << app.displayName << L"\n";
        std::wcout << L"    Version : " << app.version << L"\n";
    }
    else {
        std::wcout << L"    Status  : Not installed\n";
    }
    std::wcout << L"\n";

    // 2. Check NDIS Filter Driver (GigE Vision)
    std::wcout << L"[2] GigE Vision NDIS Filter Driver\n";
    DriverInfo gevCore = QueryDriverService(L"ids_gevcore");
    if (gevCore.installed) {
        std::wcout << L"    Status   : Installed\n";
        std::wcout << L"    Service  : " << gevCore.serviceName << L"\n";
        std::wcout << L"    Desc     : " << gevCore.displayName << L"\n";
        std::wcout << L"    Version  : " << gevCore.version << L"\n";
        std::wcout << L"    Path     : " << gevCore.driverPath << L"\n";
        std::wcout << L"    Start    : " << StartTypeToString(gevCore.startType) << L"\n";
    }
    else {
        std::wcout << L"    Status   : Not installed\n";
    }
    std::wcout << L"\n";

    // 3. Check USB3 Vision Core Driver
    std::wcout << L"[3] USB3 Vision Kernel Driver\n";
    DriverInfo u3vCore = QueryDriverService(L"ids_u3vcore");
    if (u3vCore.installed) {
        std::wcout << L"    Status   : Installed\n";
        std::wcout << L"    Service  : " << u3vCore.serviceName << L"\n";
        std::wcout << L"    Desc     : " << u3vCore.displayName << L"\n";
        std::wcout << L"    Version  : " << u3vCore.version << L"\n";
        std::wcout << L"    Path     : " << u3vCore.driverPath << L"\n";
        std::wcout << L"    Start    : " << StartTypeToString(u3vCore.startType) << L"\n";
    }
    else {
        std::wcout << L"    Status   : Not installed\n";
    }
    std::wcout << L"\n=========================================\n";

    return 0;
}
