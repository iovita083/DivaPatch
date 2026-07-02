#!/usr/bin/env python3
"""
patch_diva.py - Patch diva.exe to load plugins/*.dva at startup

Backs up diva.exe -> diva.exe.bak, then patches in place.

Usage: python patch_diva.py diva.exe
"""

import struct, sys, os, shutil


def align_up(n, a):
    return (n + a - 1) & ~(a - 1)


def patch(path):
    # Backup first
    bak = path + '.bak'
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print(f"Backed up -> {bak}")
    else:
        print(f"Backup already exists: {bak}")

    with open(bak, 'rb') as f:
        orig = bytearray(f.read())

    # ── Parse PE ──────────────────────────────────────────────────────────────
    e_lfanew     = struct.unpack_from('<I', orig, 0x3C)[0]
    nt           = e_lfanew
    opt_off      = nt + 24
    num_sec_off  = nt + 6
    num_sec      = struct.unpack_from('<H', orig, num_sec_off)[0]
    opt_hdr_size = struct.unpack_from('<H', orig, nt + 20)[0]
    ep_rva       = struct.unpack_from('<I', orig, opt_off + 16)[0]
    image_base   = struct.unpack_from('<Q', orig, opt_off + 24)[0]
    sect_align   = struct.unpack_from('<I', orig, opt_off + 32)[0]
    file_align   = struct.unpack_from('<I', orig, opt_off + 36)[0]
    image_size_off = opt_off + 56

    sec_tbl_off = opt_off + opt_hdr_size
    sections = []
    for i in range(num_sec):
        s = sec_tbl_off + i * 40
        sections.append({
            'vsize':  struct.unpack_from('<I', orig, s + 8)[0],
            'vaddr':  struct.unpack_from('<I', orig, s + 12)[0],
            'rawsize':struct.unpack_from('<I', orig, s + 16)[0],
            'rawoff': struct.unpack_from('<I', orig, s + 20)[0],
        })

    assert struct.unpack_from('<H', orig, opt_off)[0] == 0x20B, "Not a PE32+ (x64) exe"

    def rva_to_off(rva):
        for sec in sections:
            if sec['vaddr'] <= rva < sec['vaddr'] + sec['vsize']:
                return sec['rawoff'] + (rva - sec['vaddr'])
        raise ValueError(f"RVA {rva:#x} not mapped")

    # ── Find IAT slots ────────────────────────────────────────────────────────
    needed = {
        'LoadLibraryW', 'FindFirstFileW', 'FindNextFileW', 'FindClose',
        'GetModuleFileNameW', 'SetCurrentDirectoryW', 'GetProcAddress',
    }
    iat_rvas = {}
    import_rva = struct.unpack_from('<I', orig, opt_off + 112 + 8)[0]
    off = rva_to_off(import_rva)
    while True:
        orig_thunk  = struct.unpack_from('<I', orig, off)[0]
        name_rva    = struct.unpack_from('<I', orig, off + 12)[0]
        first_thunk = struct.unpack_from('<I', orig, off + 16)[0]
        off += 20
        if name_rva == 0:
            break
        dll = ''
        n = rva_to_off(name_rva)
        while orig[n]: dll += chr(orig[n]); n += 1
        if dll.upper() != 'KERNEL32.DLL':
            continue
        t = rva_to_off(orig_thunk or first_thunk)
        j = 0
        while True:
            thunk = struct.unpack_from('<Q', orig, t)[0]
            if thunk == 0: break
            if not (thunk & (1 << 63)):
                fn = ''
                n = rva_to_off(thunk & 0x7FFFFFFFFFFFFFFF) + 2
                while orig[n]: fn += chr(orig[n]); n += 1
                if fn in needed:
                    iat_rvas[fn] = first_thunk + j * 8
            t += 8; j += 1

    assert not (needed - set(iat_rvas)), f"Missing IAT: {needed - set(iat_rvas)}"
    iat = {fn: image_base + rva for fn, rva in iat_rvas.items()}

    # ── New section location ──────────────────────────────────────────────────
    last = sections[-1]
    new_vaddr    = align_up(last['vaddr'] + last['vsize'], sect_align)
    new_rawoff   = len(orig)
    stub_base_va = image_base + new_vaddr

    assert new_rawoff % file_align == 0
    assert sections[0]['rawoff'] - (sec_tbl_off + num_sec * 40) >= 40, "No room for section header"

    # ── Data ──────────────────────────────────────────────────────────────────
    strings = bytearray()
    slabels = {}

    def add_wstr(name, s):
        slabels[name] = len(strings)
        strings.extend((s + '\0').encode('utf-16-le'))

    def add_astr(name, s):
        slabels[name] = len(strings)
        strings.extend((s + '\0').encode('ascii'))

    def add_buf(name, size):
        slabels[name] = len(strings)
        strings.extend(b'\x00' * size)

    add_wstr('sfx_pattern', 'plugins\\*.dva')
    add_wstr('sfx_plugins', 'plugins\\')
    add_astr('initdva',     'InitializeDVA')
    add_buf ('wfd',         592)   # WIN32_FIND_DATAW
    add_buf ('gamedir',     1024)
    add_buf ('pathbuf',     1024)

    # ── Code builder ──────────────────────────────────────────────────────────
    code   = bytearray()
    fixups = []

    def here(): return len(code)
    def emit(b): code.extend(b if isinstance(b, (bytes, bytearray)) else bytes([b]))

    def call_iat(fn):
        fix_at = here() + 2
        emit(b'\xFF\x15\x00\x00\x00\x00')
        fixups.append(('iat', fix_at, fn, here()))

    def lea_rcx(label):
        fix_at = here() + 3
        emit(b'\x48\x8D\x0D\x00\x00\x00\x00')
        fixups.append(('data', fix_at, label, here()))

    def lea_rdx(label):
        fix_at = here() + 3
        emit(b'\x48\x8D\x15\x00\x00\x00\x00')
        fixups.append(('data', fix_at, label, here()))

    def lea_r8(label):
        fix_at = here() + 3
        emit(b'\x4C\x8D\x05\x00\x00\x00\x00')
        fixups.append(('data', fix_at, label, here()))

    def jz32():
        p = here(); emit(b'\x0F\x84\x00\x00\x00\x00'); return p

    def jnz32():
        p = here(); emit(b'\x0F\x85\x00\x00\x00\x00'); return p

    def jmp32():
        p = here(); emit(b'\xE9\x00\x00\x00\x00'); return p

    def patch32(p, target):
        sz = 6 if code[p] == 0x0F else 5
        disp = target - (p + sz)
        assert -(1<<31) <= disp < (1<<31)
        struct.pack_into('<i', code, p + (2 if code[p] == 0x0F else 1), disp)

    def jz8():
        p = here(); emit(b'\x74\x00'); return p

    def jnz8():
        p = here(); emit(b'\x75\x00'); return p

    def patch8(p, target):
        d = target - (p + 2)
        assert -128 <= d <= 127
        code[p + 1] = d & 0xFF

    def emit_wcopy():
        """Copy wide string rsi->rdi including null. rdi left AT the null."""
        top = here()
        emit(b'\x66\x8B\x06')       # mov ax, [rsi]
        emit(b'\x66\x89\x07')       # mov [rdi], ax
        emit(b'\x48\x83\xC6\x02')   # add rsi, 2
        emit(b'\x48\x83\xC7\x02')   # add rdi, 2
        emit(b'\x66\x85\xC0')       # test ax, ax
        patch32(jnz32(), top)
        emit(b'\x48\x83\xEF\x02')   # sub rdi, 2  (back to null position)

    def emit_strip_filename():
        """Scan rdi forward to null, back to last '\\', null-terminate after it."""
        find_end = here()
        emit(b'\x66\x8B\x07')       # mov ax, [rdi]
        emit(b'\x66\x85\xC0')       # test ax, ax
        jz_end = jz8()
        emit(b'\x48\x83\xC7\x02')   # add rdi, 2
        patch32(jmp32(), find_end)
        patch8(jz_end, here())
        scan_back = here()
        emit(b'\x48\x83\xEF\x02')   # sub rdi, 2
        emit(b'\x66\x8B\x07')       # mov ax, [rdi]
        emit(b'\x66\x83\xF8\x5C')   # cmp ax, '\\'
        jz_slash = jz8()
        patch32(jmp32(), scan_back)
        patch8(jz_slash, here())
        emit(b'\x48\x83\xC7\x02')           # add rdi, 2
        emit(b'\x66\xC7\x07\x00\x00')       # mov word [rdi], 0

    # ── Prologue ──────────────────────────────────────────────────────────────
    # RSP at EP entry: X where X%16==8 (OS "called" the EP).
    # 8 pushes (64 bytes): still X%16==8; sub rsp,0x28 -> X-104, %16==0.
    # RSP is 16-aligned before every CALL. Correct per ABI.
    emit(b'\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57')  # push rbp/rbx/rsi/rdi/r12-r15
    emit(b'\x48\x83\xEC\x28')   # sub rsp, 0x28

    # GetModuleFileNameW(NULL, gamedir, 512) -> absolute exe path
    emit(b'\x48\x33\xC9')               # xor rcx, rcx
    lea_rdx('gamedir')
    emit(b'\x49\x89\xD5')               # mov r13, rdx   ; r13 = gamedir ptr (preserved)
    emit(b'\x41\xB8\x00\x02\x00\x00')   # mov r8d, 512
    call_iat('GetModuleFileNameW')

    # Strip filename -> "C:\game\"
    emit(b'\x4C\x89\xEF')               # mov rdi, r13
    emit_strip_filename()

    # SetCurrentDirectoryW(gamedir)
    emit(b'\x4C\x89\xE9')               # mov rcx, r13
    call_iat('SetCurrentDirectoryW')

    # r14 = pathbuf (preserved)
    lea_r8('pathbuf')
    emit(b'\x4D\x89\xC6')               # mov r14, r8

    # FindFirstFileW(gamedir + "plugins\*.dva", &wfd)
    emit(b'\x4C\x89\xEE')               # mov rsi, r13
    emit(b'\x4C\x89\xF7')               # mov rdi, r14
    emit_wcopy()
    lea_rcx('sfx_pattern')
    emit(b'\x48\x89\xCE')               # mov rsi, rcx
    emit_wcopy()
    emit(b'\x4C\x89\xF1')               # mov rcx, r14
    lea_rdx('wfd')
    call_iat('FindFirstFileW')
    emit(b'\x49\x89\xC4')               # mov r12, rax   ; r12 = hFind
    emit(b'\x49\x83\xFC\xFF')           # cmp r12, -1
    jz_nofiles = jz32()

    # ── Plugin load loop ──────────────────────────────────────────────────────
    loop_top = here()

    lea_rcx('wfd')
    emit(b'\x48\x89\xCE')               # mov rsi, rcx

    # Skip directories
    emit(b'\x8B\x06')                   # mov eax, [rsi]  ; dwFileAttributes
    emit(b'\xA8\x10')                   # test al, 0x10   ; FILE_ATTRIBUTE_DIRECTORY
    jnz_skip = jnz32()

    # Skip macOS metadata (._*)
    emit(b'\x8A\x46\x2C')               # mov al, [rsi+0x2C]  ; cFileName[0] lo byte
    emit(b'\x3C\x2E')                   # cmp al, '.'
    jnz_notdot = jnz8()
    emit(b'\x8A\x46\x2E')               # mov al, [rsi+0x2E]  ; cFileName[1] lo byte
    emit(b'\x3C\x5F')                   # cmp al, '_'
    jnz_notunder = jnz8()
    jmp_meta = jmp32()
    not_meta = here()
    patch8(jnz_notdot,   not_meta)
    patch8(jnz_notunder, not_meta)

    # pathbuf = gamedir + "plugins\" + cFileName
    emit(b'\x4C\x89\xEE')               # mov rsi, r13
    emit(b'\x4C\x89\xF7')               # mov rdi, r14
    emit_wcopy()
    lea_rcx('sfx_plugins')
    emit(b'\x48\x89\xCE')
    emit_wcopy()
    lea_rcx('wfd')
    emit(b'\x48\x89\xCE')
    emit(b'\x48\x83\xC6\x2C')           # add rsi, 0x2C  ; &cFileName[0]
    emit_wcopy()

    # LoadLibraryW(pathbuf)
    emit(b'\x4C\x89\xF1')               # mov rcx, r14
    call_iat('LoadLibraryW')
    emit(b'\x49\x89\xC7')               # mov r15, rax
    emit(b'\x4D\x85\xFF')               # test r15, r15
    jz_fail = jz32()

    # Restore cwd to gamedir (DVA may have changed it)
    emit(b'\x4C\x89\xE9')               # mov rcx, r13
    call_iat('SetCurrentDirectoryW')

    # GetProcAddress(r15, "InitializeDVA") and call if present
    emit(b'\x4C\x89\xF9')               # mov rcx, r15
    lea_rdx('initdva')
    call_iat('GetProcAddress')
    emit(b'\x48\x85\xC0')               # test rax, rax
    jz_noinit = jz8()
    emit(b'\xFF\xD0')                   # call rax
    patch8(jz_noinit, here())

    # FindNextFileW(r12, &wfd)
    find_next = here()
    patch32(jz_fail,  find_next)
    patch32(jmp_meta, find_next)
    patch32(jnz_skip, find_next)
    emit(b'\x4C\x89\xE1')               # mov rcx, r12
    lea_rdx('wfd')
    call_iat('FindNextFileW')
    emit(b'\x85\xC0')                   # test eax, eax
    patch32(jnz32(), loop_top)

    # FindClose(r12)
    done = here()
    patch32(jz_nofiles, done)
    emit(b'\x4C\x89\xE1')               # mov rcx, r12
    call_iat('FindClose')

    # ── Epilogue ──────────────────────────────────────────────────────────────
    emit(b'\x48\x83\xC4\x28')                                    # add rsp, 0x28
    emit(b'\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5F\x5E\x5B\x5D')  # pop r15-r12/rdi/rsi/rbx/rbp

    # Replay original EP instructions with absolute targets (original relative
    # operands would be wrong from our new VA, so decode and re-encode them)
    ep_file_off  = sections[0]['rawoff'] + (ep_rva - sections[0]['vaddr'])
    call_disp    = struct.unpack_from('<i', orig, ep_file_off + 5)[0]
    jmp_disp     = struct.unpack_from('<i', orig, ep_file_off + 14)[0]
    orig_call_va = (image_base + ep_rva + 9  + call_disp) & 0xFFFFFFFFFFFFFFFF
    orig_jmp_va  = (image_base + ep_rva + 18 + jmp_disp)  & 0xFFFFFFFFFFFFFFFF

    emit(b'\x48\x83\xEC\x28')
    emit(b'\x48\xB8' + struct.pack('<Q', orig_call_va))  # movabs rax, crt_init
    emit(b'\xFF\xD0')                                    # call rax
    emit(b'\x48\x83\xC4\x28')
    emit(b'\x48\xB8' + struct.pack('<Q', orig_jmp_va))   # movabs rax, wmainCRTStartup
    emit(b'\xFF\xE0')                                    # jmp rax

    # ── Resolve fixups ────────────────────────────────────────────────────────
    while len(code) % 8: code.append(0xCC)
    data_base_off = len(code)
    code.extend(strings)
    data_base_va = stub_base_va + data_base_off

    for (kind, fix_off, target, insn_end) in fixups:
        tva  = iat[target] if kind == 'iat' else data_base_va + slabels[target]
        disp = tva - (stub_base_va + insn_end)
        assert -(1<<31) <= disp < (1<<31), f"Displacement OOR for '{target}'"
        struct.pack_into('<i', code, fix_off, disp)

    while len(code) % file_align: code.append(0)
    sec_rawsize = len(code)

    # ── Write patched exe ─────────────────────────────────────────────────────
    data = bytearray(orig)

    sh = bytearray(40)
    sh[0:8] = b'.loader\x00'
    struct.pack_into('<I', sh, 8,  sec_rawsize)
    struct.pack_into('<I', sh, 12, new_vaddr)
    struct.pack_into('<I', sh, 16, sec_rawsize)
    struct.pack_into('<I', sh, 20, new_rawoff)
    struct.pack_into('<I', sh, 36, 0xE0000020)   # CODE|EXECUTE|READ|WRITE
    data[sec_tbl_off + num_sec * 40 : sec_tbl_off + num_sec * 40 + 40] = sh
    struct.pack_into('<H', data, num_sec_off, num_sec + 1)
    struct.pack_into('<I', data, image_size_off, align_up(new_vaddr + sec_rawsize, sect_align))
    data[ep_file_off:ep_file_off + 14] = b'\xFF\x25\x00\x00\x00\x00' + struct.pack('<Q', stub_base_va)
    data.extend(code)

    with open(path, 'wb') as f:
        f.write(data)

    print(f"Patched:      {path}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} diva.exe")
        sys.exit(1)
    patch(sys.argv[1])
