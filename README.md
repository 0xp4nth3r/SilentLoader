# Windows Shellcode Loader and Havoc C2 Execution

This project demonstrates a custom Windows shellcode loader designed to execute payloads in-memory while evading Microsoft Defender and establishing a connection to a Havoc C2 teamserver.

## Key Features

- Shellcode allocation and execution using native Windows APIs
- Real-time AV evasion (tested against Windows Defender)
- Successful callback and beacon interaction with Havoc C2 framework
- BOF (Beacon Object File) integration to enumerate privileges and network details

## Files

- `shell.exe` — Custom C/C++ based shellcode runner
- `webloader.exe` — Loader deployed via Havoc for initial access
- Screenshots showcasing live execution and callback

## Tested On

- **Target OS**: Windows 10 (x64)
- **C2 Framework**: Havoc [Version 0.7]

## Execution Flow

1. Shellcode is embedded within `shell.exe` and executed using Windows API (`VirtualAlloc`, `CreateThread`, etc.)
2. The loader bypasses basic Defender protections.
3. Once executed, it connects back to the Havoc teamserver.
4. BOF tasks executed: privilege enumeration, `ipconfig`, etc.


## Disclaimer

This tool is intended for educational and authorized red team use only. Unauthorized usage against systems you do not own or have explicit permission to test is illegal.

