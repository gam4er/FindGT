#include <windows.h>
#include <aclapi.h>
#include <authz.h>
#include <msiquery.h>
#include <sddl.h>
#include <exception>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "authz.lib")
#pragma comment(lib, "msi.lib")

namespace
{
    const wchar_t* const SourceName = L"FindGT";
    const wchar_t* const ServiceName = L"FindGT";

    void Log(MSIHANDLE install, INSTALLMESSAGE type, const std::wstring& message)
    {
        MSIHANDLE record = MsiCreateRecord(1);
        if (record == 0)
        {
            return;
        }

        MsiRecordSetStringW(record, 0, L"[1]");
        MsiRecordSetStringW(record, 1, message.c_str());
        MsiProcessMessage(install, type, record);
        MsiCloseHandle(record);
    }

    UINT Fail(MSIHANDLE install, const wchar_t* operation, DWORD error)
    {
        Log(
            install,
            INSTALLMESSAGE_ERROR,
            std::wstring(operation) + L" failed with Win32 error " +
                std::to_wstring(error) + L".");
        return ERROR_INSTALL_FAILURE;
    }

    bool GetCustomActionData(MSIHANDLE install, std::wstring& value)
    {
        DWORD length = 0;
        wchar_t placeholder = L'\0';
        UINT result = MsiGetPropertyW(
            install,
            L"CustomActionData",
            &placeholder,
            &length);
        if (result != ERROR_MORE_DATA && result != ERROR_SUCCESS)
        {
            return false;
        }

        std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1, L'\0');
        DWORD capacity = length + 1;
        result = MsiGetPropertyW(
            install,
            L"CustomActionData",
            buffer.data(),
            &capacity);
        if (result != ERROR_SUCCESS)
        {
            return false;
        }

        value.assign(buffer.data(), capacity);
        return !value.empty();
    }

    bool SplitPaths(
        const std::wstring& data,
        std::wstring& messageFile,
        std::wstring& executable)
    {
        const size_t separator = data.find(L'|');
        if (separator == std::wstring::npos)
        {
            return false;
        }

        messageFile = data.substr(0, separator);
        executable = data.substr(separator + 1);
        return !messageFile.empty() && !executable.empty();
    }

    std::vector<std::wstring> Split(
        const std::wstring& value,
        wchar_t separator)
    {
        std::vector<std::wstring> parts;
        size_t start = 0;
        while (start <= value.length())
        {
            const size_t end = value.find(separator, start);
            parts.push_back(value.substr(
                start,
                end == std::wstring::npos
                    ? std::wstring::npos
                    : end - start));
            if (end == std::wstring::npos)
            {
                break;
            }

            start = end + 1;
        }

        return parts;
    }

    bool IsBooleanProperty(const std::wstring& value)
    {
        return value == L"0" || value == L"1";
    }

    const char* JsonBoolean(const std::wstring& value)
    {
        return value == L"1" ? "true" : "false";
    }

    bool IsSafeFindGtRoot(const std::filesystem::path& path)
    {
        if (!path.is_absolute() ||
            (path.has_root_path() && path == path.root_path()))
        {
            return false;
        }

        return _wcsicmp(path.filename().c_str(), L"FindGT") == 0;
    }

    DWORD UninstallSecuritySource();

    DWORD InstallSecuritySource(
        const std::wstring& messageFile,
        const std::wstring& executable)
    {
        AUTHZ_SOURCE_SCHEMA_REGISTRATION registration = {};
        registration.dwFlags = 0;
        registration.szEventSourceName = const_cast<PWSTR>(SourceName);
        registration.szEventMessageFile =
            const_cast<PWSTR>(messageFile.c_str());
        registration.szEventAccessStringsFile =
            const_cast<PWSTR>(messageFile.c_str());
        registration.szExecutableImagePath =
            const_cast<PWSTR>(executable.c_str());
        registration.dwObjectTypeNameCount = 0;

        if (AuthzInstallSecurityEventSource(0, &registration))
        {
            return ERROR_SUCCESS;
        }

        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS)
        {
            return error;
        }

        error = UninstallSecuritySource();
        if (error != ERROR_SUCCESS)
        {
            return error;
        }

        return AuthzInstallSecurityEventSource(0, &registration)
            ? ERROR_SUCCESS
            : GetLastError();
    }

    DWORD UninstallSecuritySource()
    {
        if (AuthzUninstallSecurityEventSource(0, SourceName))
        {
            return ERROR_SUCCESS;
        }

        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? ERROR_SUCCESS
            : error;
    }
}

#define FINDGT_CA_CATCH(operation) \
    catch (const std::exception&) \
    { \
        return Fail(install, operation, ERROR_UNHANDLED_EXCEPTION); \
    } \
    catch (...) \
    { \
        return Fail(install, operation, ERROR_UNHANDLED_EXCEPTION); \
    }

extern "C" __declspec(dllexport) UINT __stdcall InstallAuthzSource(
    MSIHANDLE install) try
{
    std::wstring data;
    std::wstring messageFile;
    std::wstring executable;
    if (!GetCustomActionData(install, data) ||
        !SplitPaths(data, messageFile, executable))
    {
        return Fail(install, L"Read InstallAuthzSource CustomActionData", ERROR_INVALID_DATA);
    }

    const DWORD error = InstallSecuritySource(messageFile, executable);
    if (error != ERROR_SUCCESS)
    {
        return Fail(install, L"AuthzInstallSecurityEventSource", error);
    }

    Log(install, INSTALLMESSAGE_INFO, L"Registered FindGT Security event source.");
    return ERROR_SUCCESS;
}
FINDGT_CA_CATCH(L"InstallAuthzSource")

extern "C" __declspec(dllexport) UINT __stdcall RollbackInstallAuthzSource(
    MSIHANDLE install) try
{
    const DWORD error = UninstallSecuritySource();
    return error == ERROR_SUCCESS
        ? ERROR_SUCCESS
        : Fail(install, L"AuthzUninstallSecurityEventSource rollback", error);
}
FINDGT_CA_CATCH(L"RollbackInstallAuthzSource")

extern "C" __declspec(dllexport) UINT __stdcall UninstallAuthzSource(
    MSIHANDLE install) try
{
    const DWORD error = UninstallSecuritySource();
    if (error != ERROR_SUCCESS)
    {
        return Fail(install, L"AuthzUninstallSecurityEventSource", error);
    }

    Log(install, INSTALLMESSAGE_INFO, L"Unregistered FindGT Security event source.");
    return ERROR_SUCCESS;
}
FINDGT_CA_CATCH(L"UninstallAuthzSource")

extern "C" __declspec(dllexport) UINT __stdcall RollbackUninstallAuthzSource(
    MSIHANDLE install) try
{
    std::wstring data;
    std::wstring messageFile;
    std::wstring executable;
    if (!GetCustomActionData(install, data) ||
        !SplitPaths(data, messageFile, executable))
    {
        return Fail(install, L"Read rollback CustomActionData", ERROR_INVALID_DATA);
    }

    const DWORD error = InstallSecuritySource(messageFile, executable);
    return error == ERROR_SUCCESS
        ? ERROR_SUCCESS
        : Fail(install, L"AuthzInstallSecurityEventSource rollback", error);
}
FINDGT_CA_CATCH(L"RollbackUninstallAuthzSource")

extern "C" __declspec(dllexport) UINT __stdcall ConfigureServiceRecovery(
    MSIHANDLE install) try
{
    SC_HANDLE manager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT);
    if (manager == nullptr)
    {
        return Fail(install, L"OpenSCManager", GetLastError());
    }

    SC_HANDLE service = OpenServiceW(
        manager,
        ServiceName,
        SERVICE_CHANGE_CONFIG);
    if (service == nullptr)
    {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        return Fail(install, L"OpenService", error);
    }

    SC_ACTION actions[3] =
    {
        { SC_ACTION_RESTART, 30000 },
        { SC_ACTION_RESTART, 60000 },
        { SC_ACTION_RESTART, 300000 }
    };
    SERVICE_FAILURE_ACTIONSW failureActions = {};
    failureActions.dwResetPeriod = 86400;
    failureActions.cActions = ARRAYSIZE(actions);
    failureActions.lpsaActions = actions;

    BOOL success = ChangeServiceConfig2W(
        service,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        &failureActions);
    DWORD error = success ? ERROR_SUCCESS : GetLastError();

    if (success)
    {
        SERVICE_FAILURE_ACTIONS_FLAG flag = { TRUE };
        success = ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            &flag);
        error = success ? ERROR_SUCCESS : GetLastError();
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!success)
    {
        return Fail(install, L"ChangeServiceConfig2", error);
    }

    Log(install, INSTALLMESSAGE_INFO, L"Configured FindGT service recovery.");
    return ERROR_SUCCESS;
}
FINDGT_CA_CATCH(L"ConfigureServiceRecovery")

extern "C" __declspec(dllexport) UINT __stdcall SecureProgramData(
    MSIHANDLE install) try
{
    std::wstring path;
    if (!GetCustomActionData(install, path))
    {
        return Fail(install, L"Read SecureProgramData CustomActionData", ERROR_INVALID_DATA);
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        SDDL_REVISION_1,
        &descriptor,
        nullptr))
    {
        return Fail(
            install,
            L"ConvertStringSecurityDescriptorToSecurityDescriptor",
            GetLastError());
    }

    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(
        descriptor,
        &present,
        &dacl,
        &defaulted) ||
        !present)
    {
        const DWORD error = GetLastError();
        LocalFree(descriptor);
        return Fail(install, L"GetSecurityDescriptorDacl", error);
    }

    const DWORD error = SetNamedSecurityInfoW(
        const_cast<PWSTR>(path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);
    LocalFree(descriptor);
    if (error != ERROR_SUCCESS)
    {
        return Fail(install, L"SetNamedSecurityInfo", error);
    }

    Log(install, INSTALLMESSAGE_INFO, L"Secured FindGT ProgramData directory.");
    return ERROR_SUCCESS;
}
FINDGT_CA_CATCH(L"SecureProgramData")

extern "C" __declspec(dllexport) UINT __stdcall WriteInitialConfiguration(
    MSIHANDLE install) try
{
    std::wstring data;
    if (!GetCustomActionData(install, data))
    {
        return Fail(install, L"Read WriteInitialConfiguration CustomActionData", ERROR_INVALID_DATA);
    }

    const std::vector<std::wstring> values = Split(data, L'|');
    if (values.size() != 6 ||
        !IsBooleanProperty(values[1]) ||
        !IsBooleanProperty(values[2]) ||
        !IsBooleanProperty(values[4]) ||
        !IsBooleanProperty(values[5]) ||
        (values[3] != L"Off" &&
         values[3] != L"SuspiciousOnly" &&
         values[3] != L"All"))
    {
        return Fail(install, L"Validate initial configuration properties", ERROR_INVALID_DATA);
    }

    std::ostringstream json;
    json
        << "{\r\n"
        << "  \"SchemaVersion\": 1,\r\n"
        << "  \"EnabledLogonTypes\": [3, 10],\r\n"
        << "  \"AnalyzeExistingSessionsOnStart\": " << JsonBoolean(values[1]) << ",\r\n"
        << "  \"ReconciliationIntervalSeconds\": 60,\r\n"
        << "  \"Queue\": { \"Capacity\": 1024, \"WorkerCount\": 1 },\r\n"
        << "  \"RetryDelaysMilliseconds\": [0, 250, 1000, 3000, 10000],\r\n"
        << "  \"PowerfulOnly\": {\r\n"
        << "    \"Enabled\": " << JsonBoolean(values[5]) << ",\r\n"
        << "    \"PrivilegedUserRids\": [500],\r\n"
        << "    \"PrivilegedGroupRids\": [512, 518, 519],\r\n"
        << "    \"ExactSids\": [\"S-1-5-32-544\"],\r\n"
        << "    \"AdditionalSids\": []\r\n"
        << "  },\r\n"
        << "  \"Output\": {\r\n"
        << "    \"OperationalEventLog\": { \"Enabled\": " << JsonBoolean(values[2]) << " },\r\n"
        << "    \"SecurityEventLog\": { \"Mode\": \"";

    const char* securityMode = values[3] == L"Off"
        ? "Off"
        : (values[3] == L"All" ? "All" : "SuspiciousOnly");
    json << securityMode;
    json
        << "\" },\r\n"
        << "    \"Json\": {\r\n"
        << "      \"Enabled\": " << JsonBoolean(values[4]) << ",\r\n"
        << "      \"Directory\": \"%ProgramData%\\\\FindGT\\\\Logs\"\r\n"
        << "    }\r\n"
        << "  },\r\n"
        << "  \"Exclusions\": { \"UserSids\": [], \"AccountNames\": [], \"Domains\": [] }\r\n"
        << "}\r\n";

    HANDLE file = CreateFileW(
        values[0].c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return Fail(install, L"Create initial configuration", GetLastError());
    }

    const std::string content = json.str();
    DWORD written = 0;
    const BOOL writeSucceeded = WriteFile(
        file,
        content.data(),
        static_cast<DWORD>(content.size()),
        &written,
        nullptr);
    const BOOL flushSucceeded = writeSucceeded
        ? FlushFileBuffers(file)
        : FALSE;
    DWORD error = ERROR_SUCCESS;
    if (!writeSucceeded)
    {
        error = GetLastError();
    }
    else if (written != static_cast<DWORD>(content.size()))
    {
        error = ERROR_WRITE_FAULT;
    }
    else if (!flushSucceeded)
    {
        error = GetLastError();
    }
    CloseHandle(file);
    if (error != ERROR_SUCCESS)
    {
        return Fail(install, L"Write initial configuration", error);
    }

    Log(install, INSTALLMESSAGE_INFO, L"Wrote initial FindGT configuration.");
    return ERROR_SUCCESS;
}
FINDGT_CA_CATCH(L"WriteInitialConfiguration")

extern "C" __declspec(dllexport) UINT __stdcall CleanupData(
    MSIHANDLE install) try
{
    std::wstring data;
    if (!GetCustomActionData(install, data))
    {
        return Fail(install, L"Read CleanupData CustomActionData", ERROR_INVALID_DATA);
    }

    const std::vector<std::wstring> values = Split(data, L'|');
    if (values.size() != 3 ||
        !IsBooleanProperty(values[1]) ||
        !IsBooleanProperty(values[2]))
    {
        return Fail(install, L"Validate CleanupData properties", ERROR_INVALID_DATA);
    }

    std::error_code error;
    const std::filesystem::path root =
        std::filesystem::weakly_canonical(values[0], error);
    if (error || !IsSafeFindGtRoot(root))
    {
        return Fail(install, L"Validate FindGT ProgramData path", ERROR_INVALID_DATA);
    }

    if (values[1] == L"0")
    {
        std::filesystem::remove_all(root / L"Config", error);
        if (error)
        {
            return Fail(install, L"Remove FindGT configuration", error.value());
        }
    }

    if (values[2] == L"0")
    {
        std::filesystem::remove_all(root / L"State", error);
        if (error)
        {
            return Fail(install, L"Remove FindGT state", error.value());
        }

        std::filesystem::remove_all(root / L"Logs", error);
        if (error)
        {
            return Fail(install, L"Remove FindGT logs", error.value());
        }
    }

    Log(install, INSTALLMESSAGE_INFO, L"Applied FindGT data-retention policy.");
    return ERROR_SUCCESS;
}
FINDGT_CA_CATCH(L"CleanupData")

#undef FINDGT_CA_CATCH
