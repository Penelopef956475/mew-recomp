#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elf2macho_dylib.py —— 把 AArch64 Android ELF 共享库无损封装成 Mach-O MH_DYLIB。

设计要点（对应《Mewgenics ELF转MachO iOS 重链接完整方案》）：
  * 三个 PT_LOAD 段原样搬到 __TEXT / __DATA_CONST / __DATA，
    段的 vmaddr 按页对齐，但**内容**仍落在 ELF 的原始相对偏移上，
    因此 .so 内部所有 b/bl、adrp+add 相对引用天然有效，不需要改指令。
  * R_AARCH64_RELATIVE  -> LC_DYLD_INFO_ONLY rebase（槽里写 addend，dyld 再加 slide）
  * JUMP_SLOT/ABS64/GLOB_DAT -> bind
        SDL_*                 -> SDL3.framework
        PASSTHROUGH（数学/内存/字符串）-> /usr/lib/libSystem.B.dylib
        其余 bionic/POSIX/Android -> @rpath/libbionic_shim.dylib（符号名加 _bionic_ 前缀）
  * TLSDESC -> 绑定到 libbionic_shim 的 _bionic_tlsdesc_resolver
  * 导出表（export trie）里放上所有已定义全局符号，保证 dlsym(SDL_main) 可用。

用法:
    python3 tools/elf2macho_dylib.py libmain.so -o libmew_relinked.dylib \
        --platform ios|macos [--fixups classic|chained] [--verbose]
"""
import argparse
import struct
import sys

# ---------------- ELF 常量 ----------------
PT_LOAD, PT_DYNAMIC, PT_TLS, PT_GNU_EH_FRAME = 1, 2, 7, 0x6474E550
DT_NULL, DT_NEEDED, DT_INIT, DT_FINI = 0, 1, 12, 13
DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 25, 27
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ = 5, 6, 7, 8
DT_RELAENT, DT_SYMENT = 9, 11
DT_JMPREL, DT_PLTRELSZ, DT_PLTREL = 23, 2, 20
DT_HASH, DT_GNU_HASH = 4, 0x6FFFFEF5

R_AARCH64_ABS64 = 257
R_AARCH64_PREL32 = 261
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027
R_AARCH64_TLSDESC = 1031

# ---------------- Mach-O 常量 ----------------
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0
MH_DYLIB = 6
MH_TWOLEVEL = 0x80
MH_DYLDLINK = 0x4
MH_NOUNDEFS = 0x1
MH_NO_REEXPORTED_DYLIBS = 0x00200000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_DYLD_INFO_ONLY = 0x80000022
LC_BUILD_VERSION = 0x32
LC_LOAD_DYLINKER = 0xE
LC_UUID = 0x1B

PLATFORM_MACOS, PLATFORM_IOS = 1, 2
S_ZEROFILL = 0x1
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_REGULAR, S_CSTRING_LITERALS, S_4BYTE_LITERALS = 0x0, 0x2, 0x3

# 可以直接 1:1 绑定 Darwin 的数学/内存/字符串/时间函数（方案 §8）
PASSTHROUGH = set("""
_exit abort acos asin atan atan2 atof atoi atoll btowc calloc closelog cos exp exp2
fchmod fchmodat free freelocale frexp getenv getpid iswalpha_l iswblank_l iswcntrl_l
iswdigit_l iswlower_l iswprint_l iswpunct_l iswspace_l iswupper_l iswxdigit_l link
localeconv log log2 malloc mbrlen mbrtowc mbsnrtowcs mbsrtowcs mbtowc memchr memcmp
memcpy memmove memset newlocale nl_langinfo pathconf posix_memalign pow realloc remove
sched_yield setenv setlocale sin sleep strcasecmp strchr strcmp strcoll_l strdup
strftime_l strlen strncasecmp strncmp strrchr strstr strtod strtof strtok_r strtol
strtoll strtoll_l strtoul strtoull strtoull_l strxfrm_l symlink tan time timegm
towlower towlower_l towupper towupper_l unlinkat uselocale usleep wcrtomb wcscoll_l
wcslen wcsnrtombs wcstod wcstof wcstol wcstoll wcstoul wcstoull wcsxfrm_l wctob
wmemchr wmemcmp
""".split())


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v):
    out = bytearray()
    more = True
    while more:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


class Elf:
    def __init__(self, data):
        self.d = data
        if data[:4] != b'\x7fELF' or data[4] != 2:
            raise SystemExit('not ELF64')
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        if self.e_machine != 183:
            raise SystemExit('not AArch64 (machine=%d)' % self.e_machine)
        self.ph = []
        for i in range(self.e_phnum):
            o = self.e_phoff + i * 56
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', data, o)
            self.ph.append(dict(type=t, flags=fl, off=off, va=va, fsz=fsz, msz=msz, align=al))
        self.loads = [p for p in self.ph if p['type'] == PT_LOAD]
        self.tls = next((p for p in self.ph if p['type'] == PT_TLS), None)
        self.ehframe = next((p for p in self.ph if p['type'] == PT_GNU_EH_FRAME), None)
        self.sections = self._sections()
        self.dyn = self._dynamic()
        self._symbols()
        self._relocs()

    # ---- 节 ----
    def _sections(self):
        if not self.e_shoff:
            return []
        raw = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * 64
            name, typ, flags, addr, off, size, link, info, al, ent = struct.unpack_from('<IIQQQQIIQQ', self.d, o)
            raw.append(dict(name_off=name, type=typ, flags=flags, addr=addr, off=off,
                            size=size, link=link, ent=ent))
        stro = raw[self.e_shstrndx]['off']
        for s in raw:
            n = self.d[stro + s['name_off']:]
            s['name'] = n[:n.index(b'\0')].decode('latin1')
        return raw

    def sect(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def _dynamic(self):
        self.dynv = {}
        seg = next((p for p in self.ph if p['type'] == PT_DYNAMIC), None)
        if not seg:
            return
        o = seg['off']
        while True:
            tag, val = struct.unpack_from('<qQ', self.d, o)
            if tag == DT_NULL:
                break
            self.dynv.setdefault(tag, val)
            o += 16

    def vaddr_to_off(self, va):
        for p in self.loads:
            if p['va'] <= va < p['va'] + p['msz']:
                return p['off'] + (va - p['va'])
        return None

    def _symbols(self):
        self.symtab = []
        syma = self.dynv.get(DT_SYMTAB)
        stra = self.dynv.get(DT_STRTAB)
        if not syma or not stra:
            return
        so = self.vaddr_to_off(stra)
        self.strtab_off = so
        # 符号个数：用 hash 表或 rela 最大索引推断
        count = 0
        if DT_HASH in self.dynv:
            ho = self.vaddr_to_off(self.dynv[DT_HASH])
            count = struct.unpack_from('<I', self.d, ho + 4)[0]
        if not count:
            maxs = 0
            for rel_off, rel_sz in self._rela_ranges():
                for i in range(0, rel_sz, 24):
                    info = struct.unpack_from('<Q', self.d, rel_off + i + 8)[0]
                    maxs = max(maxs, info >> 32)
            count = maxs + 1
        to = self.vaddr_to_off(syma)
        for i in range(count):
            o = to + i * 24
            name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.d, o)
            s = self.d[so + name:]
            nm = s[:s.index(b'\0')].decode('latin1') if name else ''
            self.symtab.append(dict(name=nm, info=info, shndx=shndx, value=value, size=size))

    def _rela_ranges(self):
        out = []
        r = self.dynv.get(DT_RELA)
        if r:
            sz = self.dynv.get(DT_RELASZ, 0)
            o = self.vaddr_to_off(r)
            if o is not None and sz:
                out.append((o, sz))
        j = self.dynv.get(DT_JMPREL)
        if j and self.dynv.get(DT_PLTREL, 0) == 7:
            sz = self.dynv.get(DT_PLTRELSZ, 0)
            o = self.vaddr_to_off(j)
            if o is not None and sz:
                out.append((o, sz))
        return out

    def _relocs(self):
        self.relocs = []
        for off, sz in self._rela_ranges():
            for i in range(0, sz, 24):
                r_off, r_info, r_add = struct.unpack_from('<QQq', self.d, off + i)
                self.relocs.append(dict(off=r_off, type=(r_info & 0xffffffff), sym=r_info >> 32, add=r_add))


# ---------------- 符号路由 ----------------
def route(name):
    if name.startswith('SDL_'):
        return 'sdl'
    if name in PASSTHROUGH:
        return 'system'
    return 'shim'


def shim_name(name):
    # 一律 '_bionic_' + name：C 侧的定义就是 bionic_<name>，Mach-O 加前导下划线后
    # 正好等于这个名字。之前对 __ 开头的符号少写一个下划线（'_bionic' + '__x'），
    # 而 C 里写的是 bionic___x / ASM 里写的是 _bionic___x —— 三方不一致，dlopen
    # 时会直接 "symbol not found"。
    return '_bionic_' + name             # stat -> _bionic_stat, __errno -> _bionic___errno


class MachO:
    PAGE = 0x4000

    def __init__(self, elf, platform, verbose=False):
        self.elf = elf
        self.platform = platform
        self.verbose = verbose
        self.base = 0
        self.dlls = []          # 依赖库名（按序）
        self.ordinal = {}       # name -> ordinal
        self.segments = []
        self.exports = []       # (name, addr)
        self.rebases = []       # (seg_index_section_off, addr_offset_value)
        self.binds = []         # (slot_va, symbol, addend, kind)

    # ---- 段规划 ----
    def plan(self):
        elf = self.elf
        segs = []
        for p in elf.loads:
            page_va = p['va'] & ~(self.PAGE - 1)
            lead = p['va'] - page_va
            segs.append(dict(elf=p, page_va=page_va, lead=lead,
                             vm=page_va, fsz=p['fsz'], msz=p['msz']))
        self.segments = segs
        # 文件名
        self.seg_names = ['__TEXT', '__DATA_CONST', '__DATA']
        # 依赖库
        self.dlls = ['/usr/lib/libSystem.B.dylib',
                     '@rpath/SDL3.framework/SDL3',
                     '@rpath/libbionic_shim.dylib']
        for i, n in enumerate(self.dlls):
            self.ordinal[n] = i + 1

    # ---- 收集 export / rebase / bind ----
    def collect(self):
        elf = self.elf
        for s in elf.symtab:
            if not s['name'] or s['shndx'] == 0:
                continue
            if s['info'] & 0x0f not in (1, 2, 10):   # GLOBAL/WEAK/IFUNC
                continue
            self.exports.append((s['name'], s['value'], s['info'] & 0xf))
        for r in elf.relocs:
            t = r['type']
            if t == R_AARCH64_RELATIVE:
                self.rebases.append((r['off'], r['add']))
            elif t in (R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64, R_AARCH64_GLOB_DAT):
                if r['sym'] < len(elf.symtab):
                    se = elf.symtab[r['sym']]
                    if se['shndx'] != 0:
                        # 本 DSO 内部符号：目标 = st_value + addend（按镜像整体平移修正）
                        self.rebases.append((r['off'], se['value'] + r['add']))
                    else:
                        self.binds.append((r['off'], se['name'], r['add'], t))
                self.internal_relocs = getattr(self, 'internal_relocs', 0) + 1
            elif t == R_AARCH64_TLSDESC:
                # ELF AArch64 TLSDESC 的 GOT 槽是 16 字节描述符：
                #   [slot+0] = resolver 地址（运行时 bind 成 _bionic_tlsdesc_resolver）
                #   [slot+8] = 描述符参数，也就是 .tbss 内的槽偏移 = TLS 符号 st_value + r_addend
                # 之前这里只写 0，resolver 拿到的 offset 永远是 0，所有 TLS 变量叠在一起。
                se = elf.symtab[r['sym']] if r['sym'] < len(elf.symtab) else None
                tls_off = (se['value'] if se else 0) + r['add']
                self.binds.append((r['off'], '__tlsdesc__', tls_off, t))
            elif t == R_AARCH64_PREL32:
                continue  # 段内相对，布局保留即天然正确
            else:
                if self.verbose:
                    sys.stderr.write('[warn] 未处理重定位类型 %d @0x%x\n' % (t, r['off']))

    # ---- 生成 Mach-O ----
    def emit(self):
        elf = self.elf
        segs = self.segments
        page = self.PAGE
        shift = align(0x1000, page)          # 预留给 header/load commands 的整页
        self._shift = shift

        # ---------- 1) 段放置 ----------
        # 规则：ELF VA -> 新地址 统一 +shift；段的 vm/fileoff 页对齐，内容偏移 lead。
        #       __TEXT 从 0 起把 header 包进去。
        buf = bytearray(shift)
        placed = []
        for i, s_ in enumerate(segs):
            lead = s_['lead']
            if i == 0:
                vm = 0
                fileoff = 0
                content = shift
                fsz = align(shift + s_['fsz'], page)   # 尾部补零到页界，避免 codesign 抱怨 __TEXT 空洞
                msz = align(shift + s_['msz'], page)
            else:
                vm = shift + s_['page_va']
                fileoff = vm
                content = vm + lead
                fsz = lead + s_['fsz']
                msz = align(lead + s_['msz'], page)
            need = content + s_['fsz'] - len(buf)
            if need > 0:
                buf.extend(b'\0' * need)
            src = elf.d[elf.loads[i]['off']: elf.loads[i]['off'] + s_['fsz']]
            buf[content:content + len(src)] = src
            if content + s_['msz'] > len(buf):
                buf.extend(b'\0' * (content + s_['msz'] - len(buf)))
            if vm + msz > len(buf):
                buf.extend(b'\0' * (vm + msz - len(buf)))
            placed.append(dict(vm=vm, fileoff=fileoff, content_off=content, lead=lead,
                               fsz=fsz, msz=msz))
        elf_base = shift                     # ELF VA 0 在新镜像中的地址
        self.elf_base = elf_base

        def seg_of_va(va):
            for i, p_ in enumerate(placed):
                if p_['vm'] <= va < p_['vm'] + p_['msz']:
                    return i, va - p_['vm']
            return None, None

        # rebase/bind opcode 里的 segIndex 其实是「全局节索引」，不是段索引。
        # __TEXT 有 __text/__eh_frame 两节，所以 __DATA_CONST 的节索引 = 2，__DATA = 3。
        # 低 4 位是**段索引**（0=__TEXT, 1=__DATA_CONST, 2=__DATA）；
        # 之前报 bad segIndex 是因为数据段 nsects=0，LLVM 的段表里没收录它们。
        SECTIONS_PER_SEG = [2, 1, 1]
        SECIDX = [0, 1, 2]   # 段索引

        # ---------- 2) rebase / bind ----------
        rebase_blob = bytearray()
        for va, add in sorted(self.rebases):
            si, so = seg_of_va(va + elf_base)
            if si is None:
                continue
            if si == 0:
                # 只读段里的内部指针：写死即可（不行 rebase，dyld 不允许改 __TEXT）
                struct.pack_into('<Q', buf, va + elf_base, (add + elf_base) & 0xFFFFFFFFFFFFFFFF)
                continue
            rebase_blob += bytes([0x20 | (SECIDX[si] & 0xF)]) + uleb(so) + bytes([0x51])   # SET_SEGMENT_AND_OFFSET_ULEB(seg=si) + DO_REBASE_IMM_TIMES(1)
            struct.pack_into('<Q', buf, va + elf_base, (add + elf_base) & 0xFFFFFFFFFFFFFFFF)

        bind_blob = bytearray()
        shim_syms = []
        for va, sym, add, kind in sorted(self.binds):
            if kind == R_AARCH64_TLSDESC:
                dll, sym_out = '@rpath/libbionic_shim.dylib', '_bionic_tlsdesc_resolver'
                # 描述符第二个 8 字节 = .tbss 槽偏移（add 就是上面算好的 tls_off）
                slot2 = va + 8 + elf_base
                if slot2 + 8 <= len(buf):
                    struct.pack_into('<Q', buf, slot2, add & 0xFFFFFFFFFFFFFFFF)
            elif not sym:
                continue
            else:
                k = route(sym)
                if k == 'sdl':
                    dll, sym_out = '@rpath/SDL3.framework/SDL3', '_' + sym
                elif k == 'system':
                    dll, sym_out = '/usr/lib/libSystem.B.dylib', '_' + sym
                else:
                    dll, sym_out = '@rpath/libbionic_shim.dylib', shim_name(sym)
                    shim_syms.append(sym)
            si, so = seg_of_va(va + elf_base)
            if si is None:
                continue
            ordv = self.ordinal[dll]
            # SET_DYLIB_ORDINAL_IMM：低 4 位就是序号本身，**不能再跟一个字节**
            # （之前写成 [0x11, 序号]，多出的那 1 字节被 dyld/LLVM 当成下一条
            #  opcode；shim 的序号是 3 → 0x03 = BIND_OPCODE_DONE，整张 bind 表
            #  在第一项就被判定结束，所以 --bind 永远只输出 0 条。）
            assert 0 < ordv < 16, '依赖库序号超出 SET_DYLIB_ORDINAL_IMM: %d' % ordv
            bind_blob += bytes([0x10 | ordv])
            if add:
                bind_blob += bytes([0x60]) + sleb(add)
            bind_blob += bytes([0x40]) + sym_out.encode() + b'\0'   # flags=0, 名字紧随
            bind_blob += bytes([0x51])
            bind_blob += bytes([0x70 | (SECIDX[si] & 0xF)]) + uleb(so)   # SET_SEGMENT_AND_OFFSET_ULEB
            bind_blob += bytes([0x90])
            struct.pack_into('<Q', buf, va + elf_base, 0)

        # ---------- 3) __LINKEDIT：symtab / strtab / export trie ----------
        linkedit_start = align(len(buf), page)
        buf.extend(b'\0' * (linkedit_start - len(buf)))

        strtab = bytearray(b' \0')            # Mach-O 要求 0 号为空
        symtab = bytearray()

        def add_str(s):
            off = len(strtab)
            strtab.extend(s.encode() + b'\0')
            return off

        for name, addr, typ in sorted(set(self.exports)):
            n = add_str('_' + name)
            n_type = 0x0F if (typ & 0x0f) == 2 else 0x0E   # N_WEAK_DEF / N_SECT|N_EXT
            symtab += struct.pack('<IBBHQ', n, n_type, 1, 1, addr + elf_base)

        symoff = len(buf)
        buf.extend(symtab)
        stroff = len(buf)
        buf.extend(strtab)
        buf.extend(b'\0' * (align(len(buf), 8) - len(buf)))
        trie_off = len(buf)
        # Darwin 约定：export trie 里的 C 符号名带前导 '_'
        trie = _build_trie(sorted(set(('_' + n, a + elf_base, t) for n, a, t in self.exports)))
        buf.extend(trie)
        rb_off = len(buf)
        buf.extend(rebase_blob)
        bd_off = len(buf)
        buf.extend(bind_blob)
        buf.extend(b'\0' * (align(len(buf), page) - len(buf)))
        linkedit_size = len(buf) - linkedit_start

        # ---------- 4) load commands ----------
        def sect(name, segname, addr, size, off, flags, align_pow=2):
            return struct.pack('<16s16sQQIIIIIIII', name.encode(), segname.encode(),
                               addr, size, off, align_pow, 0, 0, flags, 0, 0, 0)

        seg_cmds = bytearray()
        for i, p_ in enumerate(placed):
            name = self.seg_names[i] if i < len(self.seg_names) else '__SEG%d' % i
            secs = bytearray()
            if i == 0:
                ts = elf.sect('.text')
                ehp = elf.ehframe
                if ts:
                    secs += sect('__text', '__TEXT', elf_base + ts['addr'], ts['size'],
                                 elf_base + ts['addr'], S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS, 4)
                if ehp:
                    secs += sect('__eh_frame', '__TEXT', elf_base + ehp['va'], ehp['fsz'],
                                 elf_base + ehp['va'], S_REGULAR, 3)
            # 节的 offset+size 必须落在段的 filesize 之内（否则 LLVM/dyld 报
            # "size field of section 0 greater than the segment"），所以只覆盖文件部分；
            # 段 memsz>filesz 的 .bss 尾部由 dyld 自动零填，不需要额外节。
            if i in (1, 2):
                segname = '__DATA_CONST' if i == 1 else '__DATA'
                base = p_['vm']
                lead = p_['lead']
                # 1) 前导填充区 [vm, vm+lead)
                if lead > 0:
                    secs += sect('__pad', segname, base, lead, p_['fileoff'], S_REGULAR, 3)
                # 2) 文件部分
                secs += sect('__data', segname, base + lead, p_['fsz'] - lead,
                             p_['fileoff'] + lead, S_REGULAR, 3)
                # 3) bss 尾部（memsz > filesz）：S_ZEROFILL，offset 必须为 0
                bss = p_['msz'] - p_['fsz']
                if bss > 0:
                    secs += sect('__bss', segname, base + p_['fsz'], bss, 0, S_ZEROFILL, 3)
            nsec = len(secs) // 80
            prot = 5 if i == 0 else 3
            maxprot = 5 if i == 0 else 3
            seg_cmds += struct.pack('<II16sQQQQIIII', LC_SEGMENT_64, 72 + len(secs), name.encode(),
                                    p_['vm'], p_['msz'], p_['fileoff'], p_['fsz'],
                                    maxprot, prot, nsec, 0)
            seg_cmds += secs
        # __LINKEDIT
        seg_cmds += struct.pack('<II16sQQQQIIII', LC_SEGMENT_64, 72, b'__LINKEDIT',
                                linkedit_start, linkedit_size, linkedit_start, linkedit_size, 7, 5, 0, 0)

        def dylib_cmd(cmd, path):
            body = path.encode() + b'\0'
            ln = align(24 + len(body), 8)
            return struct.pack('<IIIIII', cmd, ln, 24, 2, 0x10000, 0x10000) + body + b'\0' * (ln - 24 - len(body))

        cmds = bytearray(seg_cmds)
        cmds += dylib_cmd(LC_ID_DYLIB, '@rpath/libmew_relinked.dylib')
        for d in self.dlls:
            cmds += dylib_cmd(LC_LOAD_DYLIB, d)
        # LC_DYLD_INFO_ONLY 共 12 个 uint32 = 48 字节（含 export_off/size）
        cmds += struct.pack('<IIIIIIIIIIII', LC_DYLD_INFO_ONLY, 48,
                            rb_off, len(rebase_blob), bd_off, len(bind_blob),
                            0, 0, 0, 0, trie_off, len(trie))
        cmds += struct.pack('<IIIIII', LC_SYMTAB, 24, symoff, len(symtab) // 16, stroff, len(strtab))
        cmds += struct.pack('<II', LC_UUID, 24) + bytes(range(16))
        plat = PLATFORM_IOS if self.platform == 'ios' else PLATFORM_MACOS
        cmds += struct.pack('<IIIIII', LC_BUILD_VERSION, 24, plat, 0x000F0000, 0, 0)
        # 命令条数按构造顺序显式计数（不再回走字节流，避免 cmdsize 解析偏差）
        # 段(含 __LINKEDIT) + LC_ID_DYLIB + LOAD_DYLIB×N + DYLD_INFO + SYMTAB + UUID + BUILD_VERSION
        ncmd = len(placed) + 1 + 1 + len(self.dlls) + 4
        # 自检：逐条走一遍，确保 cmdsize 之和 == len(cmds)
        _o, _n, _sum = 0, 0, 0
        while _o + 8 <= len(cmds):
            _sz = struct.unpack_from('<I', cmds, _o + 4)[0]
            if _sz < 8 or _o + _sz > len(cmds):
                raise SystemExit('load command 结构错乱 @%d size=%d' % (_o, _sz))
            _o += _sz
            _n += 1
            _sum += _sz
        if _o != len(cmds) or _n != ncmd:
            raise SystemExit('load commands 计数不一致: walked=%d/%d bytes=%d/%d' % (_n, ncmd, _o, len(cmds)))

        if len(cmds) > shift:
            raise SystemExit('load commands 超出 header 预留: %d > %d' % (len(cmds), shift))

        import os
        if os.environ.get('DBG'):
            print('[dbg] len(seg_cmds)=%d len(cmds)=%d ncmd=%d' % (len(seg_cmds), len(cmds), ncmd))
        hdr = struct.pack('<IIIIIIII', MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL,
                          MH_DYLIB, ncmd, len(cmds),
                          MH_DYLDLINK | MH_TWOLEVEL | MH_NO_REEXPORTED_DYLIBS, 0)
        buf[0:len(hdr)] = hdr
        buf[len(hdr):len(hdr) + len(cmds)] = cmds
        return bytes(buf), dict(placed=placed, rebases=len(self.rebases), binds=len(self.binds),
                                exports=len(self.exports), shim=len(set(shim_syms)),
                                elf_base=elf_base, ncmds=ncmd)

def _uleb_read(buf, p):
    v = 0
    s = 0
    while True:
        b = buf[p]
        p += 1
        v |= (b & 0x7F) << s
        if not b & 0x80:
            return v, p
        s += 7
        if s > 35:
            raise ValueError('ULEB 过长 @0x%x' % p)


def _walk_trie(trie):
    """按标准 Mach-O 布局走查 export trie，返回 {符号名: 地址}。

    任何越界、terminal 长度不符、节点偏移非法都立即抛异常——落盘前必须
    用这个函数自校验，避免又出现「LLVM 的游标落进符号名」这类不报错但
    结构已坏的情况。"""
    out = {}
    seen = set()
    stack = [(0, '')]
    max_end = 0
    while stack:
        off, prefix = stack.pop()
        if off >= len(trie):
            raise ValueError('trie 节点偏移越界: 0x%x' % off)
        if off in seen:
            raise ValueError('trie 节点被重复引用: 0x%x' % off)
        seen.add(off)
        p = off
        tsz, p = _uleb_read(trie, p)
        addr = None
        if tsz:
            end = p + tsz
            if end > len(trie):
                raise ValueError('terminal 越界 @0x%x' % off)
            _flags, p = _uleb_read(trie, p)
            addr, p = _uleb_read(trie, p)
            if p != end:
                raise ValueError('terminal 长度不符 @0x%x: 声明 %d 实占 %d'
                                 % (off, tsz, p - (end - tsz)))
            if prefix:
                out[prefix] = addr
        if p >= len(trie):
            raise ValueError('child_count 越界 @0x%x' % off)
        nc = trie[p]
        p += 1
        for _ in range(nc):
            e = trie.index(b'\0', p)
            nm = trie[p:e]
            p = e + 1
            co, p = _uleb_read(trie, p)
            if co >= len(trie):
                raise ValueError('子节点偏移越界: 0x%x -> 0x%x' % (off, co))
            stack.append((co, prefix + nm.decode('utf-8', 'surrogateescape')))
        max_end = max(max_end, p)
    if max_end != len(trie):
        raise ValueError('trie 实际使用 %d 字节，声明 %d 字节' % (max_end, len(trie)))
    return out


def _build_trie(entries):
    """export trie（标准 Mach-O 节点布局，根固定在 offset 0）：

        uleb(terminal_size)
        [terminal payload = uleb(flags=0) + uleb(addr)]   ← 紧跟 terminal_size
        uint8(child_count)
        child_count × { 边名字（含结尾 \\0）、uleb(child_offset) }

    注意 payload **不能**放到子节点偏移之后（那样 LLVM 会把 flags 那个 0x00
    当成 child_count、把地址字节当成子偏移，游标一路漂进符号名，正好就是
    之前 `inconsistent export info size: 0x73` 的来源）。

    偏移用规范变长 ULEB，节点大小依赖偏移数值，所以先不动点迭代求出每个
    节点位置，再第二遍按位置写字节；写完用 _walk_trie 走查自校验。"""
    root = {}
    for name, addr, typ in entries:
        if not name:
            continue
        cur = root
        for ch in name:
            cur = cur.setdefault(ch, {})
        cur[''] = addr

    nodes = []

    def collect(n):
        nodes.append(n)
        for k in sorted(x for x in n if x != ''):
            collect(n[k])

    collect(root)                       # 前序：根 = 0 号节点，子节点偏移必然更大
    idx = {id(n): i for i, n in enumerate(nodes)}

    payloads = []
    kids_list = []
    static = []                          # 与偏移无关的部分：terminal + child_count + 边名字
    for n in nodes:
        term = n.get('')
        payload = b'' if term is None else uleb(0) + uleb(term)
        kids = sorted(x for x in n if x != '')
        sz = len(uleb(len(payload))) + len(payload) + 1
        for k in kids:
            sz += len(k.encode()) + 1
        payloads.append(payload)
        kids_list.append(kids)
        static.append(sz)

    pos = [0] * len(nodes)
    edge_len = None
    for _ in range(8):
        lens = {}
        for i, kids in enumerate(kids_list):
            for k in kids:
                lens[(i, k)] = len(uleb(pos[idx[id(nodes[i][k])]]))
        acc = 0
        for i in range(len(nodes)):
            pos[i] = acc
            acc += static[i] + sum(lens[(i, k)] for k in kids_list[i])
        if lens == edge_len:             # 偏移长度已稳定，pos 与之一致
            break
        edge_len = lens
    else:
        raise RuntimeError('export trie 偏移长度未收敛')
    total = acc

    out = bytearray()
    for i, n in enumerate(nodes):
        kids = kids_list[i]
        out += uleb(len(payloads[i]))
        out += payloads[i]               # ← 紧跟 terminal_size
        out.append(len(kids))
        for k in kids:
            # 每个子节点：边名字（含 \0）紧接它自己的偏移，逐子交替；
            # 不能把所有名字写在一起再把所有偏移写在后面（那样 LLVM/dyld
            # 会把下一个名字的开头当成偏移 uleb 读，整棵树走歪）。
            out += k.encode() + b'\0'
            out += uleb(pos[idx[id(nodes[i][k])]])
    trie = bytes(out)
    if len(trie) != total:
        raise RuntimeError('export trie 大小与预计算不一致: %d != %d' % (len(trie), total))

    # 落盘前自校验：标准 walker 必须原样还原每一个导出
    got = _walk_trie(trie)
    want = {name: addr for name, addr, _t in entries if name}
    if got != want:
        allmiss = [k for k in want if k not in got]
        allbad = [k for k in want if k in got and got[k] != want[k]]
        raise RuntimeError('export trie 自校验失败：缺 %d 个（%r）错 %d 个（%r）'
                           % (len(allmiss), allmiss[:5], len(allbad), allbad[:5]))
    return trie


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--platform', choices=['ios', 'macos'], default='ios')
    ap.add_argument('--fixups', choices=['classic', 'chained'], default='classic')
    ap.add_argument('--verbose', action='store_true')
    a = ap.parse_args()
    data = open(a.elf, 'rb').read()
    elf = Elf(data)
    if len(elf.loads) != 3:
        print('[warn] PT_LOAD 数量 = %d（预期 3）' % len(elf.loads))
    m = MachO(elf, a.platform, a.verbose)
    m.plan()
    m.collect()
    blob, info = m.emit()
    open(a.out, 'wb').write(blob)
    print('wrote %s  %.1f MB' % (a.out, len(blob) / 1048576.0))
    print('  segments : %d' % len(info['placed']))
    for i, p in enumerate(info['placed']):
        print('   [%d] vm=0x%-9x off=0x%-9x filesz=0x%-8x memsz=0x%-8x'
              % (i, p['vm'], p['fileoff'], p['fsz'], p['msz']))
    print('  rebases  : %d' % info['rebases'])
    print('  binds    : %d (distinct shim syms %d)' % (info['binds'], info['shim']))
    print('  exports  : %d' % info['exports'])


if __name__ == '__main__':
    main()
