
import os, sys, struct, ctypes, ctypes.wintypes as W
import argparse, json, csv, datetime

# ── Win32 setup ───────────────────────────────────────────────────────────────

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ps  = ctypes.WinDLL("psapi",    use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)

# kernel32
_k32.GetCurrentProcess.restype          = ctypes.c_void_p
_k32.OpenProcess.restype                = ctypes.c_void_p
_k32.OpenProcess.argtypes               = [W.DWORD, W.BOOL, W.DWORD]
_k32.CloseHandle.argtypes               = [ctypes.c_void_p]
_k32.GetModuleHandleW.restype           = ctypes.c_void_p
_k32.GetModuleHandleW.argtypes          = [ctypes.c_wchar_p]
_k32.LoadLibraryW.restype               = ctypes.c_void_p
_k32.LoadLibraryW.argtypes              = [ctypes.c_wchar_p]
_k32.GetModuleFileNameW.restype         = W.DWORD
_k32.GetModuleFileNameW.argtypes        = [ctypes.c_void_p, ctypes.c_wchar_p, W.DWORD]
_k32.ReadProcessMemory.restype          = ctypes.c_bool
_k32.ReadProcessMemory.argtypes         = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_k32.SetConsoleMode.argtypes            = [ctypes.c_void_p, W.DWORD]
_k32.GetStdHandle.restype               = ctypes.c_void_p
_k32.GetStdHandle.argtypes              = [W.DWORD]
_k32.CreateToolhelp32Snapshot.restype   = ctypes.c_void_p
_k32.CreateToolhelp32Snapshot.argtypes  = [W.DWORD, W.DWORD]

# psapi
_ps.EnumProcessModules.restype          = ctypes.c_bool
_ps.EnumProcessModules.argtypes         = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    W.DWORD, ctypes.POINTER(W.DWORD),
]
_ps.GetModuleFileNameExW.restype        = W.DWORD
_ps.GetModuleFileNameExW.argtypes       = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, W.DWORD,
]

# advapi32
_adv.OpenProcessToken.restype           = ctypes.c_bool
_adv.OpenProcessToken.argtypes          = [
    ctypes.c_void_p, W.DWORD, ctypes.POINTER(ctypes.c_void_p),
]
_adv.LookupPrivilegeValueW.restype      = ctypes.c_bool
_adv.LookupPrivilegeValueW.argtypes     = [
    ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulonglong),
]
_adv.AdjustTokenPrivileges.restype      = ctypes.c_bool
_adv.AdjustTokenPrivileges.argtypes     = [
    ctypes.c_void_p, W.BOOL, ctypes.c_void_p,
    W.DWORD, ctypes.c_void_p, ctypes.POINTER(W.DWORD),
]


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize',              W.DWORD),
        ('cntUsage',            W.DWORD),
        ('th32ProcessID',       W.DWORD),
        ('th32DefaultHeapID',   ctypes.c_size_t),
        ('th32ModuleID',        W.DWORD),
        ('cntThreads',          W.DWORD),
        ('th32ParentProcessID', W.DWORD),
        ('pcPriClassBase',      ctypes.c_long),
        ('dwFlags',             W.DWORD),
        ('szExeFile',           ctypes.c_wchar * 260),
    ]


_k32.Process32FirstW.restype  = ctypes.c_bool
_k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
_k32.Process32NextW.restype   = ctypes.c_bool
_k32.Process32NextW.argtypes  = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]

# ── Constants ─────────────────────────────────────────────────────────────────

COMMON = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "user32.dll"]

_SCN_EXEC                = 0x20000000
_PROCESS_VM_READ         = 0x0010
_PROCESS_QUERY_INFO      = 0x0400
_TH32CS_SNAPPROCESS      = 0x00000002
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY             = 0x0008
_SE_PRIVILEGE_ENABLED    = 0x00000002
_INVALID_HANDLE          = ctypes.c_void_p(-1).value

R = '\033[1;31m'; G = '\033[1;32m'; Y = '\033[1;33m'
C = '\033[1;36m'; D = '\033[2m';    X = '\033[0m'

# ── Privilege ─────────────────────────────────────────────────────────────────


def _enable_debug_priv():
    htok = ctypes.c_void_p()
    if not _adv.OpenProcessToken(
        _k32.GetCurrentProcess(),
        _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY,
        ctypes.byref(htok),
    ):
        return
    try:
        luid = ctypes.c_ulonglong(0)
        if not _adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return
        tp = struct.pack('<IQI', 1, luid.value, _SE_PRIVILEGE_ENABLED)
        _adv.AdjustTokenPrivileges(htok, False, ctypes.create_string_buffer(tp), 0, None, None)
    finally:
        _k32.CloseHandle(htok)

# ── Process helpers ───────────────────────────────────────────────────────────


def find_pids(name: str) -> list:
    snap = _k32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snap or snap == _INVALID_HANDLE:
        return []
    pids = []
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        if _k32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                if pe.szExeFile.lower() == name.lower():
                    pids.append(pe.th32ProcessID)
                if not _k32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        _k32.CloseHandle(snap)
    return pids


def open_process(pid: int):
    h = _k32.OpenProcess(_PROCESS_VM_READ | _PROCESS_QUERY_INFO, False, pid)
    return h or None


def list_modules(hproc) -> list:
    needed = W.DWORD(0)
    _ps.EnumProcessModules(hproc, None, 0, ctypes.byref(needed))
    n = needed.value // ctypes.sizeof(ctypes.c_void_p)
    if not n:
        return []
    arr = (ctypes.c_void_p * n)()
    if not _ps.EnumProcessModules(hproc, arr, needed, ctypes.byref(needed)):
        return []
    buf  = ctypes.create_unicode_buffer(520)
    mods = []
    for base in arr:
        if base:
            _ps.GetModuleFileNameExW(hproc, ctypes.c_void_p(base), buf, 520)
            mods.append((base, buf.value))
    return mods


def _find_module(modules: list, label: str):
    ll = label.lower()
    for base, path in modules:
        if os.path.basename(path).lower() == ll:
            return base, path
    for base, path in modules:
        if ll in path.lower():
            return base, path
    return None, None

# ── Memory read ───────────────────────────────────────────────────────────────


def _read(hproc, addr: int, size: int) -> bytes:
    buf   = (ctypes.c_ubyte * size)()
    nread = ctypes.c_size_t(0)
    if _k32.ReadProcessMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(nread)):
        return bytes(buf[:nread.value])
    return b''

# ── PE parser ─────────────────────────────────────────────────────────────────


def _parse_sects(data: bytes, count: int, off: int) -> list:
    out = []
    for i in range(count):
        o   = off + i * 40
        vsz = struct.unpack_from('<I', data, o + 8)[0]
        rsd = struct.unpack_from('<I', data, o + 16)[0]
        out.append({
            'va':    struct.unpack_from('<I', data, o + 12)[0],
            'vsz':   vsz if vsz else rsd,
            'raw':   struct.unpack_from('<I', data, o + 20)[0],
            'chars': struct.unpack_from('<I', data, o + 36)[0],
        })
    return out


def _is_exec(rva: int, sects: list) -> bool:
    for s in sects:
        if s['va'] <= rva < s['va'] + s['vsz']:
            return bool(s['chars'] & _SCN_EXEC)
    return False


def _rva2off(rva: int, sects: list) -> int:
    for s in sects:
        if s['va'] <= rva < s['va'] + s['vsz']:
            return rva - s['va'] + s['raw']
    return -1


def _iter_exports(data: bytes):
    if len(data) < 0x40 or data[:2] != b'MZ':
        return
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if pe + 24 >= len(data) or data[pe:pe+4] != b'PE\x00\x00':
        return

    nsec  = struct.unpack_from('<H', data, pe + 6)[0]
    optsz = struct.unpack_from('<H', data, pe + 20)[0]
    opt   = pe + 24
    magic = struct.unpack_from('<H', data, opt)[0]

    dd_off = opt + (112 if magic == 0x020B else 96 if magic == 0x010B else -1)
    if dd_off < 0 or dd_off + 8 > len(data):
        return

    exp_rva  = struct.unpack_from('<I', data, dd_off)[0]
    exp_size = struct.unpack_from('<I', data, dd_off + 4)[0]
    if not exp_rva:
        return

    sects = _parse_sects(data, nsec, opt + optsz)
    eoff  = _rva2off(exp_rva, sects)
    if eoff < 0 or eoff + 40 > len(data):
        return

    nnames   = struct.unpack_from('<I', data, eoff + 24)[0]
    rv_funcs = struct.unpack_from('<I', data, eoff + 28)[0]
    rv_names = struct.unpack_from('<I', data, eoff + 32)[0]
    rv_ords  = struct.unpack_from('<I', data, eoff + 36)[0]

    of = _rva2off(rv_funcs, sects)
    on = _rva2off(rv_names, sects)
    oo = _rva2off(rv_ords,  sects)
    if min(of, on, oo) < 0:
        return

    for i in range(nnames):
        nrva = struct.unpack_from('<I', data, on + i * 4)[0]
        oidx = struct.unpack_from('<H', data, oo + i * 2)[0]
        frva = struct.unpack_from('<I', data, of + oidx * 4)[0]

        if exp_rva <= frva < exp_rva + exp_size:   # forwarder - skip
            continue

        noff = _rva2off(nrva, sects)
        if noff < 0:
            continue
        end  = data.find(b'\x00', noff)
        name = data[noff:end].decode('ascii', errors='replace')

        yield name, frva, sects

# ── Hook classifier ───────────────────────────────────────────────────────────


def _classify(b: bytes) -> str:
    if not b:
        return 'unreadable'
    if b[0] == 0xE9:
        return f'JMP rel32  (d= {struct.unpack_from("<i", b, 1)[0]:+d})'
    if b[0:2] == b'\xFF\x25':
        return f'JMP [RIP{struct.unpack_from("<i", b, 2)[0]:+d}]'
    if b[0:3] == b'\x48\xFF\x25':
        return f'JMP [RIP{struct.unpack_from("<i", b, 3)[0]:+d}]  (REX.W)'
    if b[0] == 0xEB:
        return f'JMP short  (d= {struct.unpack_from("<b", b, 1)[0]:+d})'
    if b[0] == 0x68 and len(b) >= 6 and b[5] == 0xC3:
        return f'PUSH+RET  (-> {struct.unpack_from("<I", b, 1)[0]:#010x})'
    if len(b) >= 12 and b[0:2] == b'\x48\xB8' and b[10:12] == b'\xFF\xE0':
        return f'MOV RAX+JMP   (-> {struct.unpack_from("<Q", b, 2)[0]:#018x})'
    if len(b) >= 12 and b[0:2] == b'\x48\xB8' and b[10:12] == b'\xFF\xD0':
        return f'MOV RAX+CALL  (-> {struct.unpack_from("<Q", b, 2)[0]:#018x})'
    if b[0] == 0xCC:
        return f'INT3 sled  ({b[:4].hex()})'
    return f'unknown  ({b[:4].hex()})'

# ── Scanner ───────────────────────────────────────────────────────────────────


def scan_module(hproc, base: int, disk_path: str, label: str,
                probe: int, quiet: bool) -> dict:
    header_printed = False

    def _hdr():
        nonlocal header_printed
        if not header_printed:
            print(f'\n{C}[*]{X} {label}')
            print(f'    base : {base:#018x}')
            print(f'    path : {disk_path}')
            header_printed = True

    if not quiet:
        _hdr()

    try:
        with open(disk_path, 'rb') as f:
            disk = f.read()
    except OSError as e:
        _hdr()
        print(f'    {R}error{X} cannot read disk image: {e}')
        return None

    hooks = []
    clean = skipped = 0

    for fname, rva, sects in _iter_exports(disk):
        if not _is_exec(rva, sects):
            skipped += 1
            continue
        foff = _rva2off(rva, sects)
        if foff < 0 or foff + probe > len(disk):
            skipped += 1
            continue
        disk_b = disk[foff:foff + probe]
        mem_b  = _read(hproc, base + rva, probe)
        if len(mem_b) < probe:
            skipped += 1
            continue
        if disk_b == mem_b:
            clean += 1
            continue

        _hdr()
        tag = _classify(mem_b)
        dh  = ' '.join(f'{v:02X}' for v in disk_b[:8])
        mh  = ' '.join(f'{v:02X}' for v in mem_b[:8])
        print(f'  {R}HOOK{X}  {fname}')
        print(f'        disk: {D}{dh}{X}')
        print(f'        mem:  {Y}{mh}{X}  <- {tag}')
        hooks.append({'function': fname, 'hook_type': tag,
                      'disk_bytes': dh, 'mem_bytes': mh})

    total = clean + len(hooks) + skipped
    sk    = f', {skipped} skipped' if skipped else ''
    if not quiet or hooks:
        _hdr()
        print(f'    {total} exports - {G}{clean} clean{X}, {R}{len(hooks)} hooked{X}{sk}')

    return {'base': f'{base:#018x}', 'path': disk_path,
            'hooks': hooks, 'clean': clean, 'skipped': skipped}

# ── Output helpers ────────────────────────────────────────────────────────────


def write_json(path: str, pid: int, proc_name: str, results: dict):
    out = {
        'timestamp': datetime.datetime.now().isoformat(),
        'pid':       pid,
        'process':   proc_name,
        'dlls':      {k: v for k, v in results.items() if v is not None},
    }
    with open(path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f'\n{G}[+]{X} JSON  -> {path}')


def write_csv(path: str, pid: int, proc_name: str, results: dict):
    rows = []
    for dll, info in results.items():
        if not info:
            continue
        for h in info['hooks']:
            rows.append({
                'pid':        pid,
                'process':    proc_name,
                'dll':        dll,
                'function':   h['function'],
                'hook_type':  h['hook_type'],
                'disk_bytes': h['disk_bytes'],
                'mem_bytes':  h['mem_bytes'],
            })
    if not rows:
        rows = [{'pid': pid, 'process': proc_name, 'dll': '',
                 'function': '', 'hook_type': 'NONE',
                 'disk_bytes': '', 'mem_bytes': ''}]
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f'{G}[+]{X} CSV   -> {path}')

# ── Entry ─────────────────────────────────────────────────────────────────────


def main():
    _k32.SetConsoleMode(_k32.GetStdHandle(-11), 7)

    ap = argparse.ArgumentParser(
        description='HookScan',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    tgt = ap.add_mutually_exclusive_group()
    tgt.add_argument('--pid',     type=int, metavar='PID',
                     help='scan a specific process by ID')
    tgt.add_argument('--process', metavar='NAME',
                     help='scan a process by name (e.g. lsass.exe)')
    ap.add_argument('dlls', nargs='*', metavar='DLL',
                    help='DLL(s) to scan (default: ntdll.dll)')
    ap.add_argument('--all',    '-a', action='store_true',
                    help='scan ntdll + kernel32 + kernelbase + advapi32 + user32')
    ap.add_argument('--loaded', '-l', action='store_true',
                    help='scan every DLL loaded in the target process')
    ap.add_argument('--json', metavar='FILE', help='write results to JSON file')
    ap.add_argument('--csv',  metavar='FILE', help='write results to CSV file')
    ap.add_argument('--probe', type=int, default=16, metavar='N',
                    help='prologue bytes to compare per function (default: 16)')
    ap.add_argument('--quiet', '-q', action='store_true',
                    help='suppress output for clean DLLs (useful with --loaded)')
    args = ap.parse_args()

    _enable_debug_priv()

 
    own_handle = False
    if args.process:
        pids = find_pids(args.process)
        if not pids:
            sys.exit(f'[-] no process named {args.process!r}')
        if len(pids) > 1:
            print(f'{Y}[!]{X} {len(pids)} processes named {args.process!r}; using first PID {pids[0]}')
        pid        = pids[0]
        proc_name  = args.process
        hproc      = open_process(pid)
        own_handle = True
        if not hproc:
            sys.exit(f'[-] cannot open PID {pid}  (err {ctypes.get_last_error()}) - try admin')
    elif args.pid:
        pid        = args.pid
        proc_name  = f'pid:{pid}'
        hproc      = open_process(pid)
        own_handle = True
        if not hproc:
            sys.exit(f'[-] cannot open PID {pid}  (err {ctypes.get_last_error()}) - try admin')
    else:
        pid       = os.getpid()
        proc_name = 'self'
        hproc     = _k32.GetCurrentProcess()

    print(f'{C}[*]{X} target: {proc_name}  (PID {pid})')

    modules = list_modules(hproc)
    if not modules:
        print(f'{Y}[!]{X} no modules enumerated - may need admin rights')


    if args.loaded:
        targets = [(os.path.basename(p).lower(), b, p) for b, p in modules]
        print(f'    {len(targets)} modules loaded')
    else:
        dll_names = COMMON if args.all else (args.dlls or ['ntdll.dll'])
        targets   = []
        for dll in dll_names:
            base, path = _find_module(modules, dll)
            if not base and not own_handle:
                # Current process: try loading the DLL if it isn't already
                h = _k32.LoadLibraryW(dll) #  AAH
                if h:
                    base = h
                    pbuf = ctypes.create_unicode_buffer(520)
                    _k32.GetModuleFileNameW(ctypes.c_void_p(h), pbuf, 520)
                    path = pbuf.value
            if base and path:
                targets.append((dll, base, path))
            else:
                print(f'{R}[-]{X} {dll} not found in target process')

    results = {}
    for label, base, path in targets:
        results[label] = scan_module(hproc, base, path, label, args.probe, args.quiet)

    total_hooks = sum(len(v['hooks']) for v in results.values() if v)
    print()
    if total_hooks:
        print(f'{R}[!]{X} {total_hooks} hook(s) detected - EDR/AV is active')
        for dll, info in results.items():
            if info and info['hooks']:
                names = ', '.join(h['function'] for h in info['hooks'])
                print(f'    {C}{dll}{X}: {names}')
    else:
        print(f'{G}[+]{X} no hooks found')

    if args.json:
        write_json(args.json, pid, proc_name, results)
    if args.csv:
        write_csv(args.csv, pid, proc_name, results)

    if own_handle:
        _k32.CloseHandle(hproc)


if __name__ == '__main__':
    if sys.platform != 'win32':
        sys.exit('Windows only')
    main()
