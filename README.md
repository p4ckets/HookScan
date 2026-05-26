# HookScan

Detect inline DLL hooks planted by EDR/AV software or malware in any Windows process.

Compares the first N bytes of each exported function **on disk** against what is actually **in memory**. Any mismatch that matches a known trampoline pattern is flagged.

---

## Requirements

- Python 3.6+
- Windows x64 (32-bit Python on 64-bit OS is not supported)
- No third-party packages — stdlib only

Admin rights are recommended. Required to scan protected processes (lsass, services, etc.).

---

## Usage

```
python hookscan.py                                    # ntdll.dll, current process
python hookscan.py --pid 1234                         # ntdll.dll in PID 1234
python hookscan.py --process lsass.exe --all          # common DLLs in lsass.exe
python hookscan.py --loaded                           # ALL loaded DLLs, current process
python hookscan.py --loaded --pid 1234                # ALL loaded DLLs in PID 1234
python hookscan.py kernel32.dll ntdll.dll             # specific DLLs, current process
python hookscan.py --all --json results.json          # also write JSON
python hookscan.py --all --csv  results.csv           # also write CSV
python hookscan.py --probe 32 --all                   # compare 32 bytes (default: 16)
python hookscan.py --loaded --quiet                   # only show hooked DLLs
```

### Flags

| Flag | Description |
|---|---|
| `--pid PID` | Scan a remote process by PID |
| `--process NAME` | Scan a remote process by name (e.g. `lsass.exe`) |
| `--all` / `-a` | Scan ntdll + kernel32 + kernelbase + advapi32 + user32 |
| `--loaded` / `-l` | Scan every DLL currently loaded in the target process |
| `--probe N` | Bytes to compare per function prologue (default: 16) |
| `--quiet` / `-q` | Suppress output for clean DLLs (useful with `--loaded`) |
| `--json FILE` | Write full results to a JSON file |
| `--csv FILE` | Write hook rows to a CSV file |

---

## Example output

```
[*] target: self  (PID 9412)
    28 modules loaded

[*] ntdll.dll
    base : 0x00007ff8a1b20000
    path : C:\Windows\System32\ntdll.dll
  HOOK  NtCreateFile
        disk: 4C 8B D1 B8 55 00 00 00
        mem:  E9 2B 14 F7 C2 00 00 00  <- JMP rel32  (d= +3274246955)
  HOOK  NtReadFile
        disk: 4C 8B D1 B8 06 01 00 00
        mem:  E9 3B 24 F7 C2 00 00 00  <- JMP rel32  (d= +3274312763)

    2367 exports - 2365 clean, 2 hooked

[*] kernel32.dll
    base : 0x00007ff89f3d0000
    path : C:\Windows\System32\kernel32.dll

    1724 exports - 1724 clean, 0 hooked

[!] 2 hook(s) detected - EDR/AV is active
    ntdll.dll: NtCreateFile, NtReadFile

[+] JSON  -> results.json
```

### JSON output format

```json
{
  "timestamp": "2025-05-19T14:32:01.123456",
  "pid": 9412,
  "process": "self",
  "dlls": {
    "ntdll.dll": {
      "base": "0x00007ff8a1b20000",
      "path": "C:\\Windows\\System32\\ntdll.dll",
      "hooks": [
        {
          "function": "NtCreateFile",
          "hook_type": "JMP rel32  (d= +3274246955)",
          "disk_bytes": "4C 8B D1 B8 55 00 00 00",
          "mem_bytes":  "E9 2B 14 F7 C2 00 00 00"
        }
      ],
      "clean": 2365,
      "skipped": 0
    }
  }
}
```

---

## Hook types detected

| Pattern | Leading bytes | Description |
|---|---|---|
| JMP rel32 | `E9 xx xx xx xx` | Most common EDR inline hook |
| JMP \[RIP+disp32\] | `FF 25 xx xx xx xx` | 64-bit indirect jump via pointer |
| REX.W JMP \[RIP+disp32\] | `48 FF 25 xx xx xx xx` | Same with REX prefix |
| JMP short | `EB xx` | Short 2-byte relative jump |
| PUSH+RET | `68 xx xx xx xx C3` | x86-era push/return trampoline |
| MOV RAX+JMP | `48 B8 ... FF E0` | Absolute 64-bit jump |
| MOV RAX+CALL | `48 B8 ... FF D0` | Absolute 64-bit call |
| INT3 sled | `CC ...` | Breakpoint (debugger or manual) |

---

## Build a standalone .exe

No Python installation required on the target machine:

```
pip install pyinstaller
pyinstaller --onefile hookscan.py
```

Binary will be at `dist\hookscan.exe`. Drop it anywhere and run it.

---

## How it works

1. Opens the target process with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`
2. Calls `EnumProcessModules` to enumerate loaded DLLs and their base addresses
3. For each target DLL, reads the PE export table from the on-disk file to get function RVAs
4. Reads the same N bytes from live process memory at `base + RVA`
5. Any mismatch is classified by its leading byte pattern

Skips non-executable sections and forwarder exports to avoid false positives.

---

## Comparison to similar tools

| Tool | Language | Remote process | All loaded DLLs | JSON output |
|---|---|---|---|---|
| **HookScan** | Python | Yes | Yes | Yes |
| pe-sieve | C++ | Yes | Yes | Yes |
| moneta | C++ | Yes | Yes | No |
| Get-InjectedThread | PowerShell | Yes | No | No |

pe-sieve is more comprehensive (kernel hooks, PE anomalies, memory implants). HookScan is a focused, dependency-free alternative for inline hook detection specifically.

---

## Limitations

- Userland hooks only — does not detect SSDT hooks, IRP hooks, or kernel callbacks
- Named exports only — ordinal-only exports are not scanned
- Reads disk image directly — DLLs loaded from memory (reflective injection) will not have a matching disk path and will be skipped
