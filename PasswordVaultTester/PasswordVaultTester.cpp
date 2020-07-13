#pragma once

#define WIN32_LEAN_AND_MEAN 

#include <iostream>

#include <windows.h>
#include <wincred.h>
#include <tchar.h>
#include <combaseapi.h>
#include <string>

#define CREDENTIAL_TYPE CRED_TYPE_GENERIC
#define CREDENTIAL_PERSIST CRED_PERSIST_LOCAL_MACHINE
constexpr auto VERBOSE = false;

struct CredentialInternal {
    std::wstring username;
    std::wstring password;
    bool error;
};

bool set_credential(
    std::wstring target,
    std::wstring username,
    std::wstring password,
    bool verbose);

CredentialInternal get_credential(std::wstring target, bool verbose);

bool delete_credential(std::wstring target, bool verbose);

extern "C" {
    struct Credential {
        wchar_t* username;
        wchar_t* password;
        bool error;
    };

    __declspec(dllexport) bool __cdecl set_credential_ext(
        const wchar_t* target,
        const wchar_t* username,
        const wchar_t* password);

    __declspec(dllexport) void __cdecl get_credential_ext(const wchar_t* target, Credential* credential);

    __declspec(dllexport) bool __cdecl delete_credential_ext(const wchar_t* target);
}

int main()
{
    std::wcout << L"--- Manage Password Vault Credentials ---" << std::endl << std::endl;

    while (true) {
        std::wstring credential_name;
        std::wstring credential_username;
        std::wstring credential_password;

        std::wcout << L"Please enter a name: ";
        std::getline(std::wcin, credential_name);
        std::wcout << std::endl;

        std::wcout << L"Please enter a username: ";
        std::getline(std::wcin, credential_username);
        std::wcout << std::endl;

        std::wcout << L"Please enter a password: ";
        std::getline(std::wcin, credential_password);
        std::wcout << std::endl;

        set_credential(credential_name, credential_username, credential_password, true);
        const auto cred = new Credential();
        get_credential_ext(credential_name.c_str(), cred);
        // delete_credential(L"test", true);

        std::wcout << L"Done!" << std::endl << std::endl;
        // TODO: break from this loop
    }

    return 0;
}

bool set_credential(std::wstring target, std::wstring username, std::wstring password, bool verbose) {
    auto password_c_str = password.c_str();
    auto target_c_str = target.c_str();
    auto username_c_str = username.c_str();

    if (verbose) {
        std::wcout << L"*** Setting credentials: ***" << std::endl
            << L"Username: " << username << ", " << std::endl
            << L"Password: " << password << ", " << std::endl
            << L"Target: " << target << "." << std::endl << std::endl;
    }

    auto scale_factor = sizeof(wchar_t) / sizeof(BYTE);
    auto wide_password_length = wcslen(password_c_str);
    auto cred_size = (wide_password_length * scale_factor) + 1;

    CREDENTIALW cred = { 0 };
    cred.Type = CREDENTIAL_TYPE;
    cred.TargetName = (LPWSTR)target_c_str;
    cred.CredentialBlobSize = (DWORD)cred_size;
    cred.CredentialBlob = (LPBYTE)password_c_str;
    cred.Persist = CREDENTIAL_PERSIST;
    cred.UserName = (LPWSTR)username_c_str;

    BOOL ok = FALSE;
    ok = CredWriteW(&cred, 0);

    if (!ok) {
        wprintf(L"Setting credentials threw error with HRESULT %d.\n", GetLastError());
        return false;
    }

    return true;
}

CredentialInternal get_credential(std::wstring target, bool verbose) {
    auto target_c_str = target.c_str();

    if (verbose) {
        std::wcout << L"*** Getting credentials: ***" << std::endl
            << L"Target: " << target << "." << std::endl << std::endl;
    }

    PCREDENTIALW pcred;
    BOOL ok = FALSE;
    ok = CredReadW((LPWSTR)target_c_str, CREDENTIAL_TYPE, 0, &pcred);

    if (!ok) {
        auto last_error = GetLastError();
        wprintf(L"Getting credentials threw error with HRESULT %d.\n");
        auto credential = CredentialInternal();
        credential.username = std::wstring();
        credential.password = std::wstring();
        credential.error = true;
    }

    auto username = pcred->UserName;
    auto credential_blob = (wchar_t*)pcred->CredentialBlob;
    auto credential_blob_size = pcred->CredentialBlobSize;

    if (verbose) {
        std::wcout << L"*** Current Credentials: ***" << std::endl
            << L"Username: " << username << ", " << std::endl
            << L"Password: " << credential_blob << ", " << std::endl
            << L"(" << credential_blob_size << " bytes)." << std::endl << std::endl;
    }

    auto result = std::wstring(credential_blob);

    CredFree(pcred);

    auto credential = CredentialInternal();
    credential.username = std::wstring(username);
    credential.password = std::wstring(credential_blob);
    credential.error = false;

    return credential;
}

bool delete_credential(std::wstring target, bool verbose) {
    auto target_c_str = target.c_str();
    BOOL ok = FALSE;

    if (verbose) {
        std::wcout << L"*** Deleting Credentials: ***" << std::endl
            << L"Target: " << target << "." << std::endl << std::endl;
    }

    ok = CredDeleteW(target_c_str, CREDENTIAL_TYPE, 0);

    if (!ok) {
        wprintf(L"Deleting credentials threw error with HRESULT %d.\n", GetLastError());
        return false;
    }

    return true;
}

void alloc_return_string(std::wstring from_string, wchar_t** to_string) {
    auto c_string = from_string.c_str();
    wchar_t* string_return = nullptr;
    auto string_size = (wcslen(c_string) * sizeof(wchar_t)) + sizeof(wchar_t);
    string_return = (wchar_t*)::CoTaskMemAlloc(string_size);
    wcscpy_s(string_return, string_size, c_string);
    *to_string = string_return;
}

bool __cdecl set_credential_ext(
    const wchar_t* target,
    const wchar_t* username,
    const wchar_t* password) {
    return set_credential(target, username, password, VERBOSE);
}

void __cdecl get_credential_ext(const wchar_t* target, Credential* credential) {
    auto result = get_credential(target, VERBOSE);

    wchar_t* username_c_str_return;
    alloc_return_string(result.username, &username_c_str_return);

    wchar_t* password_c_str_return;
    alloc_return_string(result.password, &password_c_str_return);

    credential->username = username_c_str_return;
    credential->password = password_c_str_return;
    credential->error = result.error;
}

bool __cdecl delete_credential_ext(const wchar_t* target) {
    return delete_credential(target, VERBOSE);
}