#include "lifter_core.h"

#include <Zydis/Zydis.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

// ---------------- PE ----------------
const Section* PeImage::byRva(uint32_t rva) const {
    for (const auto& s : sections)
        if (rva >= s.va && rva < s.va + std::max(s.vsize, s.rawsize)) return &s;
    return nullptr;
}

const ImportSlot* PeImage::importBySlot(uint64_t slot_va) const {
    for (const auto& im : imports)
        if (im.slot_va == slot_va) return &im;
    return nullptr;
}

bool PeImage::hasFunction(uint64_t va) const {
    // functions 按 VA 升序（.pdata 本身有序），二分
    size_t lo = 0, hi = functions.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (functions[mid].first < va) lo = mid + 1; else hi = mid;
    }
    return lo < functions.size() && functions[lo].first == va;
}

bool loadPe(const char* path, PeImage& pe, std::string* err) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { if (err) *err = "open failed"; return false; }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    pe.data.resize((size_t)n);
    size_t got = std::fread(pe.data.data(), 1, pe.data.size(), f);
    std::fclose(f);
    if (got != pe.data.size()) { if (err) *err = "short read"; return false; }

    const uint32_t peOff = *(uint32_t*)(pe.data.data() + 0x3c);
    if (std::memcmp(pe.data.data() + peOff, "PE\0\0", 4) != 0) { if (err) *err = "not PE"; return false; }
    const uint16_t nsec = *(uint16_t*)(pe.data.data() + peOff + 6);
    const uint16_t optSize = *(uint16_t*)(pe.data.data() + peOff + 20);
    const uint8_t* opt = pe.data.data() + peOff + 24;
    pe.image_base = *(uint64_t*)(opt + 24);
    pe.entry_rva = *(uint32_t*)(opt + 16);
    pe.size_of_image = *(uint32_t*)(opt + 56);
    const size_t secTab = peOff + 24 + optSize;
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint8_t* p = pe.data.data() + secTab + i * 40;
        Section s;
        char name[9] = {0};
        std::memcpy(name, p, 8);
        s.name = name;
        s.vsize = *(uint32_t*)(p + 8);
        s.va = *(uint32_t*)(p + 12);
        s.rawsize = *(uint32_t*)(p + 16);
        s.raw = *(uint32_t*)(p + 20);
        s.exec = (*(uint32_t*)(p + 36) & 0x20000000) != 0;
        pe.sections.push_back(s);
    }
    // ---- Load Config：CFG 检查/分发槽位 + GFIDS 合法间接目标表 ----
    if (!pe.sections.empty()) {
        const uint32_t ddOff = 112 + 8 * 10;   // DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
        const uint32_t lcRva = *(uint32_t*)(opt + ddOff);
        const uint32_t lcSize = *(uint32_t*)(opt + ddOff + 4);
        const Section* lsec = lcRva ? pe.byRva(lcRva) : nullptr;
        if (lsec && lcSize >= 0x80) {
            const uint8_t* lc = pe.data.data() + lsec->raw + (lcRva - lsec->va);
            pe.guard_check_va = *(uint64_t*)(lc + 0x70);
            pe.guard_dispatch_va = *(uint64_t*)(lc + 0x78);
            if (lcSize >= 0x90) {
                uint64_t tblVa = *(uint64_t*)(lc + 0x80);
                uint64_t cnt = *(uint64_t*)(lc + 0x88);
                const Section* tsec = tblVa ? pe.byRva((uint32_t)(tblVa - pe.image_base)) : nullptr;
                if (tsec && cnt && cnt < 200000) {
                    uint32_t off = tsec->raw + (uint32_t)(tblVa - pe.image_base - tsec->va);
                    for (uint64_t i = 0; i < cnt; ++i) {
                        if (off + i * 4 + 4 > tsec->raw + tsec->rawsize) break;
                        uint32_t rva = *(uint32_t*)(pe.data.data() + off + i * 4);
                        if (rva) pe.gfids.push_back(pe.image_base + rva);
                    }
                }
            }
            std::fprintf(stderr, "[cfg] check=0x%llx dispatch=0x%llx gfids=%zu\n",
                         (unsigned long long)pe.guard_check_va,
                         (unsigned long long)pe.guard_dispatch_va, pe.gfids.size());
        }
    }

    // ---- 导入表（IAT 槽位 -> DLL!API）----
    {
        const uint32_t impRva = *(uint32_t*)(opt + 120);
        const uint32_t impSize = *(uint32_t*)(opt + 124);
        if (impRva && impSize) {
            const Section* isec = pe.byRva(impRva);
            if (isec) {
                uint32_t off = isec->raw + (impRva - isec->va);
                for (int d = 0; d < 512 && off + 20 <= isec->raw + isec->rawsize; ++d, off += 20) {
                    const uint8_t* desc = pe.data.data() + off;
                    uint32_t oft = *(uint32_t*)(desc + 0);
                    uint32_t nameRva = *(uint32_t*)(desc + 12);
                    uint32_t ft = *(uint32_t*)(desc + 16);
                    if (!nameRva && !ft) break;
                    const Section* nsec = pe.byRva(nameRva);
                    if (!nsec) continue;
                    std::string dll((const char*)pe.data.data() + nsec->raw + (nameRva - nsec->va));
                    if (dll.size() > 4 && dll.substr(dll.size() - 4) == ".dll") dll.erase(dll.size() - 4);
                    // API-set 归一化：让符号名与手写垫片一致（否则弱占位会顶掉强符号）
                    {
                        std::string lower = dll;
                        for (char& ch : lower) ch = (char)std::tolower((unsigned char)ch);
                        if (lower.rfind("api-ms-win-", 0) == 0) {
                            if (lower.find("-user") != std::string::npos) dll = "USER32";
                            else if (lower.find("crt") != std::string::npos) dll = "UCRT";
                            else if (lower.find("ole") != std::string::npos) dll = "OLE32";
                            else dll = "KERNEL32";
                        }
                    }
                    for (char& c : dll) c = (char)std::toupper((unsigned char)c);
                    uint32_t nameThunk = oft ? oft : ft;
                    const Section* tsec = pe.byRva(nameThunk);
                    const Section* fsec = pe.byRva(ft);
                    if (!tsec || !fsec) continue;
                    uint32_t toff = tsec->raw + (nameThunk - tsec->va);
                    for (uint32_t i = 0;; ++i) {
                        if (toff + 8 > tsec->raw + tsec->rawsize) break;
                        uint64_t ent = *(uint64_t*)(pe.data.data() + toff + i * 8);
                        if (!ent) break;
                        if (ent & (1ull << 63)) {
                            // 按序号导入：也要建槽，否则蹦床槽位是垃圾值
                            ImportSlot im;
                            im.slot_va = pe.image_base + ft + (uint64_t)i * 8;
                            im.dll = dll;
                            im.name = "Ordinal" + std::to_string((unsigned long long)(ent & 0xFFFF));
                            pe.imports.push_back(im);
                            continue;
                        }
                        uint32_t hn = *(uint32_t*)(pe.data.data() + toff + i * 8);
                        const Section* hsec = pe.byRva(hn);
                        if (!hsec) continue;
                        const char* fnameRaw = (const char*)pe.data.data() + hsec->raw + (hn - hsec->va) + 2;
                        ImportSlot im;
                        im.slot_va = pe.image_base + ft + (uint64_t)i * 8;
                        im.dll = dll;
                        im.name = fnameRaw;
                        pe.imports.push_back(im);
                    }
                }
            }
        }
    }

    for (const auto& s : pe.sections) {
        if (s.name != ".pdata") continue;
        const uint8_t* raw = pe.data.data() + s.raw;
        for (uint32_t off = 0; off + 12 <= s.rawsize; off += 12) {
            uint32_t b = *(uint32_t*)(raw + off);
            uint32_t e = *(uint32_t*)(raw + off + 4);
            if (b && e > b) pe.functions.emplace_back(pe.image_base + b, e - b);
        }
    }
    return true;
}

// ---------------- helpers ----------------
namespace {

const char* ctype(int bytes) {
    switch (bytes) {
        case 1: return "uint8_t";
        case 2: return "uint16_t";
        case 4: return "uint32_t";
        default: return "uint64_t";
    }
}

int gprId(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH: return 0;
        case ZYDIS_REGISTER_SPL: return 4;
        case ZYDIS_REGISTER_BPL: return 5;
        case ZYDIS_REGISTER_SIL: return 6;
        case ZYDIS_REGISTER_DIL: return 7;
        case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH: return 1;
        case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH: return 2;
        case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH: return 3;
        case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: return 4;
        case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP: return 5;
        case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: return 6;
        case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: return 7;
        case ZYDIS_REGISTER_R8: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B: return 8;
        case ZYDIS_REGISTER_R9: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B: return 9;
        case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return 10;
        case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return 11;
        case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return 12;
        case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return 13;
        case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return 14;
        case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return 15;
        default: return -1;
    }
}

int xmmId(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_XMM0: return 0; case ZYDIS_REGISTER_XMM1: return 1;
        case ZYDIS_REGISTER_XMM2: return 2; case ZYDIS_REGISTER_XMM3: return 3;
        case ZYDIS_REGISTER_XMM4: return 4; case ZYDIS_REGISTER_XMM5: return 5;
        case ZYDIS_REGISTER_XMM6: return 6; case ZYDIS_REGISTER_XMM7: return 7;
        case ZYDIS_REGISTER_XMM8: return 8; case ZYDIS_REGISTER_XMM9: return 9;
        case ZYDIS_REGISTER_XMM10: return 10; case ZYDIS_REGISTER_XMM11: return 11;
        case ZYDIS_REGISTER_XMM12: return 12; case ZYDIS_REGISTER_XMM13: return 13;
        case ZYDIS_REGISTER_XMM14: return 14; case ZYDIS_REGISTER_XMM15: return 15;
        default: return -1;
    }
}

struct Emit {
    std::ostringstream out;
    std::vector<std::string> unsupported;
    int count = 0;
    bool usesRipData = false;
    bool hasCall = false;
    bool usesMemory = false;
    bool writesMemory = false;
    bool hasPrologue = false;
    bool usesNonStackMem = false;
    bool fallsOffEnd = false;
    uint32_t ptrArgMask = 0;
    bool badMemBase = false;
    uint32_t flags = 0;
    int directCalls = 0;
    bool indirectCall = false;
    bool iatCall = false;
    bool stubbed = false;
    std::vector<std::string> stubMnems;
};


std::string addrExpr(const PeImage& pe, const ZydisDecodedOperand& op, uint64_t next_rip, Emit& e);
std::string valExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& op,
                    uint64_t next_rip, Emit& e);
void storeExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& dst,
               const std::string& val, uint64_t next_rip, int bytes, Emit& e);


static bool is_xmm_reg(const ZydisDecodedOperand& o) {
    return o.type == ZYDIS_OPERAND_TYPE_REGISTER && xmmId(o.reg.value) >= 0;
}
static bool is_gpr_reg(const ZydisDecodedOperand& o) {
    return o.type == ZYDIS_OPERAND_TYPE_REGISTER && gprId(o.reg.value) >= 0;
}

// 读操作数（xmm 或内存），返回 C++ 表达式字符串；bytes = 1/2/4/8/16
static std::string sseRead(const PeImage& pe, const ZydisDecodedOperand& o,
                           uint64_t next_rip, Emit& e, int bytes) {
    if (is_xmm_reg(o)) return "ctx->xmm[" + std::to_string(xmmId(o.reg.value)) + "]";
    std::string addr = addrExpr(pe, o, next_rip, e);
    if (bytes == 4) return "g_f32(" + addr + ")";
    if (bytes == 8) return "g_f64(" + addr + ")";
    if (bytes == 16) return "g_u128(" + addr + ")";
    return "g_u64(" + addr + ")";
}

bool tryEmitSse(Emit& e, const PeImage& pe, const std::string& mn,
                const ZydisDecodedInstruction& insn,
                const ZydisDecodedOperand* ops, uint64_t next_rip) {
    if (insn.operand_count < 1) return false;
    const ZydisDecodedOperand& d0 = ops[0];
    int dx = is_xmm_reg(d0) ? xmmId(d0.reg.value) : -1;
    int dg = is_gpr_reg(d0) ? gprId(d0.reg.value) : -1;
    // 目标寄存器 id 用于写入
    auto dst = [&]() { return dx >= 0 ? ("ctx->xmm[" + std::to_string(dx) + "]") : std::string(); };

    // ---- 整数乘除/借位 ----
    if (mn == "mul" || mn == "div" || mn == "idiv") {
        int w = ops[0].size / 8;
        std::string src;
        if (is_gpr_reg(ops[0])) src = "read_reg(ctx," + std::to_string(gprId(ops[0].reg.value)) + "," + std::to_string(w) + ")";
        else src = "g_u64(" + addrExpr(pe, ops[0], next_rip, e) + ")";
        if (mn == "mul") {
            if (w == 8) {
                e.out << "  { unsigned __int128 p = (unsigned __int128)ctx->rax * (unsigned __int128)(" << src
                      << "); ctx->rax = (uint64_t)p; ctx->rdx = (uint64_t)(p >> 64); }\n";
            } else {
                unsigned mask = (w == 4) ? 0xFFFFFFFFu : (w == 2 ? 0xFFFFu : 0xFFu);
                e.out << "  { uint64_t a = ctx->rax & " << mask << "ULL, b = (" << src << ") & " << mask
                      << "ULL; uint64_t p = a * b; write_reg(ctx,0,p & " << mask << "ULL," << w
                      << "); write_reg(ctx,2,(p >> " << (w * 8) << ") & " << mask << "ULL," << w << "); }\n";
            }
        } else if (mn == "div") {
            if (w == 8) {
                e.out << "  { unsigned __int128 n = ((unsigned __int128)ctx->rdx << 64) | ctx->rax; uint64_t d = "
                      << src << "; ctx->rax = d ? (uint64_t)(n / d) : 0; ctx->rdx = d ? (uint64_t)(n % d) : 0; }\n";
            } else {
                e.out << "  { uint64_t d = (" << src << ") & 0xFFFFFFFFULL; uint64_t n = ((ctx->rdx & 0xFFFFFFFFULL) << 32) | (ctx->rax & 0xFFFFFFFFULL);"
                         " write_reg(ctx,0, d ? (n / d) : 0, 4); write_reg(ctx,2, d ? (n % d) : 0, 4); }\n";
            }
        } else {
            if (w == 8) {
                e.out << "  { __int128 n = ((__int128)(int64_t)ctx->rdx << 64) | ctx->rax; int64_t d = (int64_t)("
                      << src << "); ctx->rax = d ? (uint64_t)(n / d) : 0; ctx->rdx = d ? (uint64_t)(n % d) : 0; }\n";
            } else {
                e.out << "  { int64_t d = (int32_t)(uint32_t)(" << src << "); int64_t n = (int64_t)(int32_t)((ctx->rdx << 32) | (ctx->rax & 0xFFFFFFFFULL));"
                         " write_reg(ctx,0, d ? (uint64_t)(n / d) : 0, 4); write_reg(ctx,2, d ? (uint64_t)(n % d) : 0, 4); }\n";
            }
        }
        return true;
    }
    if (mn == "sbb") {
        int w = ops[0].size / 8;
        std::string a = valExpr(pe, insn, ops[0], next_rip, e);
        std::string b = valExpr(pe, insn, ops[1], next_rip, e);
        storeExpr(pe, insn, ops[0], "sbb_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")",
                  next_rip, w, e);
        return true;
    }

    // ---- 打包整数算术 ----
    if (mn.size() == 5 && (mn.rfind("padd", 0) == 0 || mn.rfind("psub", 0) == 0)) {
        char sz = mn[4];
        const char* T = (sz == 'b') ? "u8" : (sz == 'w') ? "u16" : (sz == 'd') ? "u32" : "u64";
        const char* CT = (sz == 'b') ? "uint8_t" : (sz == 'w') ? "uint16_t" : (sz == 'd') ? "uint32_t" : "uint64_t";
        int lanes = (sz == 'b') ? 16 : (sz == 'w') ? 8 : (sz == 'd') ? 4 : 2;
        char op = (mn[1] == 'a') ? '+' : '-';
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { uint64_t t[" << lanes << "]; for(int i=0;i<" << lanes << ";++i) t[i]=(uint64_t)((int64_t)ctx->xmm["
              << dx << "]." << T << "[i] " << op << " (int64_t)" << src << "." << T
              << "[i]); for(int i=0;i<" << lanes << ";++i) ctx->xmm[" << dx << "]." << T << "[i]=(" << CT << ")t[i]; }\n";
        return true;
    }
    if (mn == "pand" || mn == "por") {
        char opch = (mn == "pand") ? '&' : '|';
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        for (int lane = 0; lane < 2; ++lane)
            e.out << "  ctx->xmm[" << dx << "].u64[" << lane << "] = ctx->xmm[" << dx << "].u64["
                  << lane << "] " << opch << " " << src << ".u64[" << lane << "];\n";
        return true;
    }
    // ---- 打包移位（立即数或 xmm 低 64 位计数）----
    if (mn == "pslld" || mn == "psllq" || mn == "psrld" || mn == "psrlq" || mn == "psrad" || mn == "psraw") {
        bool left = (mn[2] == 'l');
        bool arith = (mn == "psrad" || mn == "psraw");
        char sz = mn[4];
        const char* T = (sz == 'd') ? "u32" : (sz == 'q') ? "u64" : "u16";
        const char* CT = (sz == 'd') ? "uint32_t" : (sz == 'q') ? "uint64_t" : "uint16_t";
        const char* ST = (sz == 'd') ? "int32_t" : (sz == 'q') ? "int64_t" : "int16_t";
        int lanes = (sz == 'q') ? 2 : (sz == 'd') ? 4 : 8;
        int bits = (sz == 'q') ? 64 : (sz == 'd') ? 32 : 16;
        std::string cnt = is_gpr_reg(ops[1]) ? ("read_reg(ctx," + std::to_string(gprId(ops[1].reg.value)) + ",8)")
                                             : std::to_string((unsigned long long)ops[1].imm.value.u);
        e.out << "  { uint64_t sh=(" << cnt << ") & " << (bits - 1) << "ULL; uint64_t t[" << lanes << "];\n";
        for (int i = 0; i < lanes; ++i) {
            e.out << "    t[" << i << "]=";
            if (left) e.out << "(uint64_t)ctx->xmm[" << dx << "]." << T << "[" << i << "] << sh";
            else if (arith) e.out << "(uint64_t)((" << ST << ")ctx->xmm[" << dx << "]." << T << "[" << i << "] >> sh)";
            else e.out << "(uint64_t)ctx->xmm[" << dx << "]." << T << "[" << i << "] >> sh";
            e.out << ";\n";
        }
        e.out << "    for(int i=0;i<" << lanes << ";++i) ctx->xmm[" << dx << "]." << T << "[i]=(" << CT << ")t[i]; }\n";
        return true;
    }
    if (mn == "psrldq" || mn == "pslldq") {
        unsigned sh = (unsigned)ops[1].imm.value.u;
        bool right = (mn == "psrldq");
        e.out << "  { uint8_t t[16]; for(int i=0;i<16;++i){ int j="
              << (right ? "i+(int)" : "i-(int)") << sh << "; t[i]=(j>=0&&j<16)? ctx->xmm[" << dx
              << "].u8[j] : 0; } for(int i=0;i<16;++i) ctx->xmm[" << dx << "].u8[i]=t[i]; }\n";
        return true;
    }
    if (mn == "pshufd") {
        unsigned imm = (unsigned)ops[1].imm.value.u;
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[0].reg.value)) + "]";
        e.out << "  { uint32_t t[4]; ";
        for (int i = 0; i < 4; ++i)
            e.out << "t[" << i << "]=" << src << ".u32[" << ((imm >> (i * 2)) & 3) << "]; ";
        e.out << "for(int i=0;i<4;++i) ctx->xmm[" << dx << "].u32[i]=t[i]; }\n";
        return true;
    }
    // ---- 打包插值/打包/乘加/掩码 ----
    if (mn == "punpcklbw" || mn == "punpcklwd" || mn == "punpckldq" ||
        mn == "punpckhbw" || mn == "punpckhwd" || mn == "punpckhdq") {
        bool hi = (mn[6] == 'h');
        char sz = mn[8];
        const char* T = (sz == 'b') ? "u8" : (sz == 'w') ? "u16" : "u32";
        const char* CT = (sz == 'b') ? "uint8_t" : (sz == 'w') ? "uint16_t" : "uint32_t";
        int lanes = (sz == 'b') ? 16 : (sz == 'w') ? 8 : 4;
        int half = lanes / 2;
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { uint64_t t[" << lanes << "]; for(int i=0;i<" << half << ";++i){ int k="
              << (hi ? "i+" + std::to_string(half) : "i") << ";"
              << " t[2*i]=ctx->xmm[" << dx << "]." << T << "[k]; t[2*i+1]=" << src << "." << T << "[k]; }"
              << " for(int i=0;i<" << lanes << ";++i) ctx->xmm[" << dx << "]." << T << "[i]=(" << CT << ")t[i]; }\n";
        return true;
    }
    if (mn == "packuswb") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { uint8_t t[16]; for(int i=0;i<8;++i){ int v=ctx->xmm[" << dx << "].u16[i]; t[i]=(uint8_t)(v<0?0:(v>255?255:v)); int w="
              << src << ".u16[i]; t[i+8]=(uint8_t)(w<0?0:(w>255?255:w)); }"
                 " for(int i=0;i<16;++i) ctx->xmm[" << dx << "].u8[i]=t[i]; }\n";
        return true;
    }
    if (mn == "pmullw") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { for(int i=0;i<8;++i) ctx->xmm[" << dx << "].u16[i]=(uint16_t)(ctx->xmm[" << dx
              << "].u16[i] * " << src << ".u16[i]); }\n";
        return true;
    }
    if (mn == "pmuludq") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { uint64_t t[2]; for(int i=0;i<2;++i) t[i]=(uint64_t)ctx->xmm[" << dx << "].u32[2*i] * (uint64_t)"
              << src << ".u32[2*i]; for(int i=0;i<2;++i) ctx->xmm[" << dx << "].u64[i]=t[i]; }\n";
        return true;
    }
    if (mn == "pmovmskb" || mn == "movmskps" || mn == "movmskpd") {
        int gd = gprId(ops[0].reg.value);
        int sx = xmmId(ops[1].reg.value);
        if (mn == "pmovmskb") {
            e.out << "  { uint32_t m=0; for(int i=0;i<16;++i) m |= ((uint32_t)(ctx->xmm[" << sx
                  << "].u8[i] >> 7) & 1u) << i; write_reg(ctx," << gd << ",m,4); }\n";
        } else if (mn == "movmskps") {
            e.out << "  { uint32_t m=0; for(int i=0;i<4;++i) m |= ((ctx->xmm[" << sx
                  << "].u32[i] >> 31) & 1u) << i; write_reg(ctx," << gd << ",m,4); }\n";
        } else {
            e.out << "  { uint32_t m=0; for(int i=0;i<2;++i) m |= ((uint32_t)(ctx->xmm[" << sx
                  << "].u64[i] >> 63) & 1u) << i; write_reg(ctx," << gd << ",m,4); }\n";
        }
        return true;
    }
    if (mn == "pcmpeqb" || mn == "pcmpeqw" || mn == "pcmpeqd" ||
        mn == "pcmpgtb" || mn == "pcmpgtw" || mn == "pcmpgtd") {
        char sz = mn[6];
        const char* T = (sz == 'b') ? "u8" : (sz == 'w') ? "u16" : "u32";
        const char* ST = (sz == 'b') ? "int8_t" : (sz == 'w') ? "int16_t" : "int32_t";
        const char* CT = (sz == 'b') ? "uint8_t" : (sz == 'w') ? "uint16_t" : "uint32_t";
        int lanes = (sz == 'b') ? 16 : (sz == 'w') ? 8 : 4;
        bool eq = (mn.rfind("pcmpeq", 0) == 0);
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { for(int i=0;i<" << lanes << ";++i) { bool c = ";
        if (eq) e.out << "ctx->xmm[" << dx << "]." << T << "[i] == " << src << "." << T << "[i]";
        else e.out << "((" << ST << ")ctx->xmm[" << dx << "]." << T << "[i]) > ((" << ST << ")" << src << "." << T << "[i])";
        e.out << "; ctx->xmm[" << dx << "]." << T << "[i] = c ? (" << CT << ")~0 : 0; } }\n";
        return true;
    }
    // ---- 打包整数 <-> 浮点转换 ----
    if (mn == "cvtdq2ps") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { float t[4]; for(int i=0;i<4;++i) t[i]=(float)(int32_t)" << src
              << ".u32[i]; for(int i=0;i<4;++i) ctx->xmm[" << dx << "].f32[i]=t[i]; }\n";
        return true;
    }
    if (mn == "cvtdq2pd") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { double t[2]; for(int i=0;i<2;++i) t[i]=(double)(int32_t)" << src
              << ".u32[i]; for(int i=0;i<2;++i) ctx->xmm[" << dx << "].f64[i]=t[i]; }\n";
        return true;
    }
    if (mn == "cvtps2pd") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { double t[2]; for(int i=0;i<2;++i) t[i]=(double)" << src
              << ".f32[i]; for(int i=0;i<2;++i) ctx->xmm[" << dx << "].f64[i]=t[i]; }\n";
        return true;
    }
    if (mn == "cvtpd2ps") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { float t[2]; for(int i=0;i<2;++i) t[i]=(float)" << src
              << ".f64[i]; for(int i=0;i<2;++i) ctx->xmm[" << dx << "].f32[i]=t[i];\n"
                 "    ctx->xmm[" << dx << "].u64[1]=0ULL; }\n";
        return true;
    }
    if (mn == "cvtps2dq" || mn == "cvttps2dq") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { uint32_t t[4]; for(int i=0;i<4;++i) t[i]=(uint32_t)sse::cvttss2si(" << src
              << ".f32[i]); for(int i=0;i<4;++i) ctx->xmm[" << dx << "].u32[i]=t[i]; }\n";
        return true;
    }
    if (mn == "mulpd" || mn == "addpd" || mn == "subpd" || mn == "divpd") {
        char opch = (mn == "mulpd") ? '*' : (mn == "addpd") ? '+' : (mn == "subpd") ? '-' : '/';
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        for (int lane = 0; lane < 2; ++lane)
            e.out << "  ctx->xmm[" << dx << "].f64[" << lane << "] = ctx->xmm[" << dx << "].f64["
                  << lane << "] " << opch << " " << src << ".f64[" << lane << "];\n";
        return true;
    }
    if (mn == "minsd" || mn == "maxsd") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  ctx->xmm[" << dx << "].f64[0] = std::" << (mn == "minsd" ? "fmin" : "fmax")
              << "(ctx->xmm[" << dx << "].f64[0], " << src << ".f64[0]);\n";
        return true;
    }
    if (mn == "movapd" || mn == "movupd") {
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  ctx->xmm[" << dx << "].u64[0]=" << src << ".u64[0]; ctx->xmm[" << dx
              << "].u64[1]=" << src << ".u64[1];\n";
        return true;
    }
    if (mn == "unpcklpd" || mn == "unpckhpd" || mn == "unpcklps" || mn == "unpckhps") {
        bool pd = (mn.substr(mn.size() - 2) == "pd");
        bool hi = (mn[5] == 'h');
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        if (pd) {
            int k = hi ? 1 : 0;
            e.out << "  { double a=ctx->xmm[" << dx << "].f64[" << k << "]; double b=" << src
                  << ".f64[" << k << "]; ctx->xmm[" << dx << "].f64[0]=a; ctx->xmm[" << dx
                  << "].f64[1]=b; }\n";
        } else {
            int k0 = hi ? 2 : 0, k1 = hi ? 3 : 1;
            e.out << "  { float a0=ctx->xmm[" << dx << "].f32[" << k0 << "], a1=ctx->xmm[" << dx
                  << "].f32[" << k1 << "]; float b0=" << src << ".f32[" << k0 << "], b1=" << src
                  << ".f32[" << k1 << "]; ctx->xmm[" << dx << "].f32[0]=a0; ctx->xmm[" << dx
                  << "].f32[1]=b0; ctx->xmm[" << dx << "].f32[2]=a1; ctx->xmm[" << dx
                  << "].f32[3]=b1; }\n";
        }
        return true;
    }
    // ---- 标量浮点 ----
    if (mn == "movss" || mn == "movsd") {
        int bytes = (mn == "movss") ? 4 : 8;
        std::string src = sseRead(pe, ops[1], next_rip, e, bytes);
        if (dx >= 0 && is_xmm_reg(ops[1])) {
            e.out << "  " << dst() << ".u64[0] = " << src << ".u64[0];\n";
        } else if (dx >= 0) {
            e.out << "  " << dst() << ".u64[0] = g_u64(" << addrExpr(pe, ops[1], next_rip, e) << ");\n";
            e.out << "  " << dst() << ".u64[1] = 0ULL;\n";
        } else {
            // store xmm/imm -> mem
            std::string srcx = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
            std::string addr = addrExpr(pe, ops[0], next_rip, e);
            if (bytes == 4) e.out << "  g_st32(" << addr << ", " << srcx << ".u32[0]);\n";
            else e.out << "  g_st64(" << addr << ", " << srcx << ".u64[0]);\n";
        }
        return true;
    }
    const bool scalar_ss = mn.size() > 3 && mn.substr(mn.size() - 2) == "ss";
    const bool scalar_sd = mn.size() > 3 && mn.substr(mn.size() - 2) == "sd";
    const char* base = nullptr;
    if (scalar_ss || scalar_sd) {
        std::string stem = mn.substr(0, mn.size() - 2);
        if (stem == "add" || stem == "sub" || stem == "mul" || stem == "div" ||
            stem == "sqrt" || stem == "min" || stem == "max") base = nullptr;
        else if (mn == "addss" || mn == "subss" || mn == "mulss" || mn == "divss" ||
                 mn == "sqrtss" || mn == "minss" || mn == "maxss") base = "ss";
        if (mn == "addss" || mn == "subss" || mn == "mulss" || mn == "divss" ||
            mn == "sqrtss" || mn == "minss" || mn == "maxss") {
            std::string a = "ctx->xmm[" + std::to_string(dx) + "].f32[0]";
            std::string b = sseRead(pe, ops[1], next_rip, e, 4);
            std::string bv = (is_xmm_reg(ops[1])) ? b + ".f32[0]"
                                                 : "g_f32(" + addrExpr(pe, ops[1], next_rip, e) + ")";
            std::string op;
            if (mn == "addss") op = a + " + " + bv;
            else if (mn == "subss") op = a + " - " + bv;
            else if (mn == "mulss") op = a + " * " + bv;
            else if (mn == "divss") op = a + " / " + bv;
            else if (mn == "sqrtss") op = "std::sqrt(" + bv + ")";
            else if (mn == "minss") op = "std::fmin(" + a + ", " + bv + ")";
            else op = "std::fmax(" + a + ", " + bv + ")";
            e.out << "  ctx->xmm[" << dx << "].f32[0] = " << op << ";\n";
            return true;
        }
        if (mn == "addsd" || mn == "subsd" || mn == "mulsd" || mn == "divsd" || mn == "sqrtsd") {
            std::string a = "ctx->xmm[" + std::to_string(dx) + "].f64[0]";
            std::string bv = (is_xmm_reg(ops[1])) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].f64[0]")
                                                  : ("g_f64(" + addrExpr(pe, ops[1], next_rip, e) + ")");
            std::string op;
            if (mn == "addsd") op = a + " + " + bv;
            else if (mn == "subsd") op = a + " - " + bv;
            else if (mn == "mulsd") op = a + " * " + bv;
            else if (mn == "divsd") op = a + " / " + bv;
            else op = "std::sqrt(" + bv + ")";
            e.out << "  ctx->xmm[" << dx << "].f64[0] = " << op << ";\n";
            return true;
        }
    }
    if (mn == "ucomiss" || mn == "comiss" || mn == "ucomisd" || mn == "comisd") {
        bool single = (mn == "ucomiss" || mn == "comiss");
        std::string a = single ? ("ctx->xmm[" + std::to_string(dx) + "].f32[0]")
                               : ("ctx->xmm[" + std::to_string(dx) + "].f64[0]");
        std::string b = single ? ((is_xmm_reg(ops[1])) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].f32[0]")
                                                       : ("g_f32(" + addrExpr(pe, ops[1], next_rip, e) + ")"))
                               : ((is_xmm_reg(ops[1])) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].f64[0]")
                                                       : ("g_f64(" + addrExpr(pe, ops[1], next_rip, e) + ")"));
        e.out << "  sse::" << (single ? "ucomiss" : "ucomisd") << "(ctx, " << a << ", " << b << ");\n";
        return true;
    }
    // ---- 类型转换 ----
    if (mn == "cvtsi2ss" || mn == "cvtsi2sd") {
        int w = ops[1].size / 8;
        std::string src = "read_reg(ctx," + std::to_string(gprId(ops[1].reg.value)) + "," + std::to_string(w) + ")";
        if (mn == "cvtsi2ss")
            e.out << "  ctx->xmm[" << dx << "].f32[0] = (float)(int64_t)" << src << ";\n";
        else
            e.out << "  ctx->xmm[" << dx << "].f64[0] = (double)(int64_t)" << src << ";\n";
        return true;
    }
    if (mn == "cvttss2si" || mn == "cvttsd2si") {
        int w = ops[0].size / 8;
        std::string src = (is_xmm_reg(ops[1])) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]." + (mn == "cvttss2si" ? "f32[0]" : "f64[0]"))
                                               : ((mn == "cvttss2si") ? ("g_f32(" + addrExpr(pe, ops[1], next_rip, e) + ")")
                                                                       : ("g_f64(" + addrExpr(pe, ops[1], next_rip, e) + ")"));
        if (mn == "cvttss2si")
            e.out << "  write_reg(ctx," << dg << ",(uint64_t)(int64_t)sse::cvttss2si(" << src << ")," << w << ");\n";
        else
            e.out << "  write_reg(ctx," << dg << ",(uint64_t)sse::cvttsd2si(" << src << ")," << w << ");\n";
        return true;
    }
    if (mn == "cvtss2sd") {
        std::string src = is_xmm_reg(ops[1]) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].f32[0]")
                                             : ("g_f32(" + addrExpr(pe, ops[1], next_rip, e) + ")");
        e.out << "  ctx->xmm[" << dx << "].f64[0] = (double)" << src << ";\n";
        return true;
    }
    if (mn == "cvtsd2ss") {
        std::string src = is_xmm_reg(ops[1]) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].f64[0]")
                                             : ("g_f64(" + addrExpr(pe, ops[1], next_rip, e) + ")");
        e.out << "  ctx->xmm[" << dx << "].f32[0] = (float)" << src << ";\n";
        return true;
    }
    // ---- 128 位搬运与位运算 ----
    if (mn == "movaps" || mn == "movups" || mn == "movdqa" || mn == "movdqu") {
        if (dx < 0 && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && is_xmm_reg(ops[1])) {
            // 存储方向：movaps [mem], xmm
            std::string addr = addrExpr(pe, ops[0], next_rip, e);
            int sx = xmmId(ops[1].reg.value);
            e.out << "  g_st64(" << addr << ", ctx->xmm[" << sx << "].u64[0]);\n"
                  << "  g_st64(" << addr << " + 8ULL, ctx->xmm[" << sx << "].u64[1]);\n";
            return true;
        }
        if (is_xmm_reg(ops[1])) {
            e.out << "  " << dst() << ".u64[0] = ctx->xmm[" << xmmId(ops[1].reg.value) << "].u64[0];\n"
                  << "  " << dst() << ".u64[1] = ctx->xmm[" << xmmId(ops[1].reg.value) << "].u64[1];\n";
        } else {
            uint64_t a = 0; (void)a;
            std::string addr = addrExpr(pe, ops[1], next_rip, e);
            e.out << "  " << dst() << ".u64[0] = g_u64(" << addr << ");\n"
                  << "  " << dst() << ".u64[1] = g_u64(" << addr << " + 8ULL);\n";
        }
        return true;
    }
    if (mn == "xorps" || mn == "xorpd" || mn == "pxor" || mn == "andps" || mn == "orps") {
        auto srcExpr = [&](int lane) -> std::string {
            if (is_xmm_reg(ops[1])) return "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].u64[" + std::to_string(lane) + "]";
            std::string addr = addrExpr(pe, ops[1], next_rip, e);
            return "g_u64(" + addr + (lane ? " + 8ULL)" : ")");
        };
        char opch = (mn == "andps") ? '&' : (mn == "orps") ? '|' : '^';
        for (int lane = 0; lane < 2; ++lane)
            e.out << "  " << dst() << ".u64[" << lane << "] = " << dst() << ".u64[" << lane << "] "
                  << opch << " " << srcExpr(lane) << ";\n";
        return true;
    }
    // ---- 打包单精度算术 ----
    if (mn == "addps" || mn == "subps" || mn == "mulps" || mn == "divps") {
        char opch = (mn == "addps") ? '+' : (mn == "subps") ? '-' : (mn == "mulps") ? '*' : '/';
        for (int lane = 0; lane < 4; ++lane) {
            std::string b = is_xmm_reg(ops[1]) ? ("ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "].f32[" + std::to_string(lane) + "]")
                                               : ("g_f32(" + addrExpr(pe, ops[1], next_rip, e) + " + " + std::to_string(lane * 4) + "ULL)");
            e.out << "  ctx->xmm[" << dx << "].f32[" << lane << "] = ctx->xmm[" << dx << "].f32["
                  << lane << "] " << opch << " " << b << ";\n";
        }
        return true;
    }
    if (mn == "shufps") {
        uint8_t imm = (uint8_t)ops[2].imm.value.u;
        std::string src = "ctx->xmm[" + std::to_string(xmmId(ops[1].reg.value)) + "]";
        e.out << "  { uint32_t t[4] = {";
        for (int i = 0; i < 4; ++i) {
            int sel = (imm >> (i * 2)) & 3;
            if (i < 2) e.out << "ctx->xmm[" << dx << "].u32[" << sel << "]";
            else e.out << src << ".u32[" << sel << "]";
            if (i < 3) e.out << ", ";
        }
        e.out << "}; for (int i=0;i<4;++i) ctx->xmm[" << dx << "].u32[i]=t[i]; }\n";
        return true;
    }
    if (mn == "movd" || mn == "movq") {
        int bytes = (mn == "movd") ? 4 : 8;
        if (is_xmm_reg(ops[0]) && is_gpr_reg(ops[1])) {
            e.out << "  ctx->xmm[" << dx << "].u64[0] = read_reg(ctx," << gprId(ops[1].reg.value) << ","
                  << bytes << ");\n  ctx->xmm[" << dx << "].u64[1] = 0ULL;\n";
            return true;
        }
        if (is_gpr_reg(ops[0]) && is_xmm_reg(ops[1])) {
            e.out << "  write_reg(ctx," << dg << ",ctx->xmm[" << xmmId(ops[1].reg.value) << "].u64[0],"
                  << bytes << ");\n";
            return true;
        }
        if (is_xmm_reg(ops[0]) && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            std::string addr = addrExpr(pe, ops[1], next_rip, e);
            e.out << "  ctx->xmm[" << dx << "].u64[0] = g_u64(" << addr << ");\n";
            return true;
        }
        if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && is_xmm_reg(ops[1])) {
            std::string addr = addrExpr(pe, ops[0], next_rip, e);
            e.out << "  g_st64(" << addr << ", ctx->xmm[" << xmmId(ops[1].reg.value) << "].u64[0]);\n";
            return true;
        }
        return false;
    }
    return false;
}

std::string hexStr(uint64_t v);

bool tryEmitCfg(Emit& e, const PeImage& pe, const std::string& mn,
                const ZydisDecodedOperand& op0, uint64_t next_rip) {
    if (op0.type != ZYDIS_OPERAND_TYPE_MEMORY || op0.mem.base != ZYDIS_REGISTER_RIP) return false;
    uint64_t slot_va = next_rip + (int64_t)op0.mem.disp.value;
    if (pe.guard_check_va && slot_va == pe.guard_check_va) {
        e.out << "  /* CFG guard_check_icall_fptr bypassed (NOP) */\n";
        return true;
    }
    if (pe.guard_dispatch_va && slot_va == pe.guard_dispatch_va) {
        if (mn == "call") {
            e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, 0x"
                  << hexStr(next_rip) << "ULL);\n";
            e.out << "  dispatch_indirect(ctx->rax, ctx, true);\n";
        } else {
            e.out << "  dispatch_indirect(ctx->rax, ctx);\n  return;\n";
        }
        return true;
    }
    return false;
}

std::string addrExpr(const PeImage& pe, const ZydisDecodedOperand& op, uint64_t next_rip, Emit& e) {
    if (op.mem.base == ZYDIS_REGISTER_RIP) {
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        e.usesRipData = true;
        return std::to_string((unsigned long long)(next_rip + d)) + "ULL /*rip*/";
    }
    // 段前缀：gs:[disp] / fs:[disp] 走伪 TEB
    if (op.mem.segment == ZYDIS_REGISTER_GS || op.mem.segment == ZYDIS_REGISTER_FS) {
        int64_t sd = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        std::string base = (op.mem.segment == ZYDIS_REGISTER_GS) ? "ctx->gs_base" : "ctx->fs_base";
        std::ostringstream ss;
        ss << "(" << base;
        if (sd >= 0) ss << " + (" << sd << "LL)";
        else ss << " - (" << (-sd) << "LL)";
        ss << ")";
        return ss.str();
    }
    // 内存基址性质分析：栈(rsp/rbp)、参数指针(rcx/rdx/r8/r9)、还是不可判定的寄存器
    {
        auto argIdxOf = [](ZydisRegister r) -> int {
            switch (r) {
                case ZYDIS_REGISTER_RCX: return 0;
                case ZYDIS_REGISTER_RDX: return 1;
                case ZYDIS_REGISTER_R8:  return 2;
                case ZYDIS_REGISTER_R9:  return 3;
                default: return -1;
            }
        };
        ZydisRegister b = op.mem.base, ix = op.mem.index;
        int bi = argIdxOf(b), ii = argIdxOf(ix);
        if (bi >= 0) e.ptrArgMask |= (1u << bi);
        if (ii >= 0) e.ptrArgMask |= (1u << ii);
        bool stackBase = (b == ZYDIS_REGISTER_RSP || b == ZYDIS_REGISTER_RBP || b == ZYDIS_REGISTER_NONE);
        if (!stackBase && bi < 0) { e.badMemBase = true; e.usesNonStackMem = true; }
        if (b == ZYDIS_REGISTER_NONE && ix == ZYDIS_REGISTER_NONE) { e.badMemBase = true; e.usesNonStackMem = true; }
        if (ix != ZYDIS_REGISTER_NONE && ii < 0) { e.badMemBase = true; e.usesNonStackMem = true; }
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        if (d < -0x4000 || d > 0x8000) e.badMemBase = true;
    }
    std::ostringstream s;
    bool any = false;
    if (op.mem.base != ZYDIS_REGISTER_NONE) {
        int b = gprId(op.mem.base);
        if (b < 0) return "0";
        s << "read_reg(ctx," << b << ",8)";
        any = true;
    }
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
        int i = gprId(op.mem.index);
        if (i < 0) return "0";
        if (any) s << " + ";
        s << "read_reg(ctx," << i << ",8)*" << (int)op.mem.scale;
        any = true;
    }
    int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
    if (d || !any) {
        if (any) s << " + ";
        s << "(" << d << "LL)";
        any = true;
    }
    (void)pe;
    return s.str();
}

std::string valExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& op,
                    uint64_t next_rip, Emit& e) {
    switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int id = gprId(op.reg.value);
            if (id >= 0) return "read_reg(ctx," + std::to_string(id) + "," + std::to_string(op.size / 8) + ")";
            int xi = xmmId(op.reg.value);
            if (xi >= 0) return "xmm_u64(ctx," + std::to_string(xi) + ")";
            return "0";
        }
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            return std::to_string((unsigned long long)op.imm.value.u) + "ULL";
        case ZYDIS_OPERAND_TYPE_MEMORY:
            return std::string("mem_read<") + ctype(op.size / 8) + ">(ctx," + addrExpr(pe, op, next_rip, e) + ")";
        default:
            return "0";
    }
}

std::string hexStr(uint64_t v);


// 片段模式下发现的额外入口（跳转目标）
std::unordered_set<uint64_t>* g_needed_entries = nullptr;
std::unordered_map<std::string, size_t>* g_stub_hist = nullptr;

// 从 PE 原始字节读 8 字节（未应用重定位，值就是原始 VA）
static bool readGuestQword(const PeImage& pe, uint64_t va, uint64_t* out);

void storeExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& dst,
               const std::string& val, uint64_t next_rip, int bytes, Emit& e) {
    (void)in;
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int id = gprId(dst.reg.value);
        if (id >= 0) { e.out << "  write_reg(ctx," << id << "," << val << "," << bytes << ");\n"; return; }
        int xi = xmmId(dst.reg.value);
        if (xi >= 0) { e.out << "  xmm_set_u64(ctx," << xi << "," << val << ");\n"; return; }
        if (e.flags & LIFT_STUB_UNKNOWN) {
            e.stubbed = true;
            if (g_stub_hist) {
                const char* rn = ZydisRegisterGetString(dst.reg.value);
                (*g_stub_hist)[std::string("reg-store:") + (rn ? rn : "?")]++;
            }
            e.out << "  UNIMPL_INSN(0x" << hexStr(next_rip) << "ULL, \"reg-store\");\n";
            return;
        }
        e.unsupported.push_back("reg-store");
        return;
    }
    if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        e.writesMemory = true;
        e.out << "  mem_write<" << ctype(bytes) << ">(ctx," << addrExpr(pe, dst, next_rip, e) << "," << val << ");\n";
        return;
    }
    e.unsupported.push_back("store");
}

std::string canonCC(const std::string& suf) {
    if (suf == "e" || suf == "z") return "z";
    if (suf == "ne" || suf == "nz") return "nz";
    if (suf == "s") return "s";
    if (suf == "ns") return "ns";
    if (suf == "c" || suf == "b" || suf == "nae") return "b";
    if (suf == "nc" || suf == "ae" || suf == "nb") return "ae";
    if (suf == "be" || suf == "na") return "be";
    if (suf == "a" || suf == "nbe") return "a";
    if (suf == "l" || suf == "nge") return "l";
    if (suf == "ge" || suf == "nl") return "ge";
    if (suf == "le" || suf == "ng") return "le";
    if (suf == "g" || suf == "nle") return "g";
    if (suf == "o") return "o";
    if (suf == "no") return "no";
    if (suf == "p" || suf == "pe") return "p";
    if (suf == "np" || suf == "po") return "np";
    return "";
}

std::string ccByCanon(const std::string& c) {
    if (c == "z") return "ctx->zf";
    if (c == "nz") return "!ctx->zf";
    if (c == "s") return "ctx->sf";
    if (c == "ns") return "!ctx->sf";
    if (c == "b") return "ctx->cf";
    if (c == "ae") return "!ctx->cf";
    if (c == "be") return "(ctx->cf || ctx->zf)";
    if (c == "a") return "(!ctx->cf && !ctx->zf)";
    if (c == "l") return "(ctx->sf != ctx->of)";
    if (c == "ge") return "(ctx->sf == ctx->of)";
    if (c == "le") return "(ctx->zf || (ctx->sf != ctx->of))";
    if (c == "g") return "(!ctx->zf && (ctx->sf == ctx->of))";
    if (c == "o") return "ctx->of";
    if (c == "no") return "!ctx->of";
    if (c == "p") return "ctx->pf";
    if (c == "np") return "!ctx->pf";
    return "";
}

std::string ccExpr(const std::string& mn) {
    if (mn.size() < 2 || mn[0] != 'j') return "";
    return ccByCanon(canonCC(mn.substr(1)));
}

// setcc / cmovcc 后缀 → 条件表达式
std::string ccSuffix(const std::string& mn, const char* prefix) {
    size_t n = std::strlen(prefix);
    if (mn.rfind(prefix, 0) != 0) return "";
    return ccByCanon(canonCC(mn.substr(n)));
}

std::string hexStr(uint64_t v) { std::ostringstream o; o << std::hex << v; return o.str(); }

static bool readGuestQword(const PeImage& pe, uint64_t va, uint64_t* out) {
    if (va < pe.image_base) return false;
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) return false;
    uint32_t off = sec->raw + (uint32_t)(va - pe.image_base - sec->va);
    if (off + 8 > sec->raw + sec->rawsize) return false;
    std::memcpy(out, pe.data.data() + off, 8);
    return true;
}
std::string shimSym(const ImportSlot& im) { return "shim_" + im.dll + "_" + im.name; }

// 目标若是 `jmp qword ptr [rip+disp]` 形式的 IAT thunk，返回对应导入槽
static const ImportSlot* resolveIatThunk(const PeImage& pe, uint64_t target) {
    const Section* sec = pe.byRva((uint32_t)(target - pe.image_base));
    if (!sec) return nullptr;
    uint32_t off = sec->raw + (uint32_t)(target - pe.image_base - sec->va);
    if (off + 6 > sec->raw + sec->rawsize) return nullptr;
    const uint8_t* p = pe.data.data() + off;
    if (p[0] == 0xFF && p[1] == 0x25) {
        int32_t disp = *(const int32_t*)(p + 2);
        uint64_t slot = target + 6 + (int64_t)disp;
        return pe.importBySlot(slot);
    }
    return nullptr;
}

}  // namespace

LiftResult liftLinearEx(const PeImage& pe, uint64_t va, uint32_t size, uint32_t flags);

LiftResult liftFunction(const PeImage& pe, uint64_t va, uint32_t size) {
    return liftLinearEx(pe, va, size, 0);
}

LiftResult liftLinearEx(const PeImage& pe, uint64_t va, uint32_t size, uint32_t flags) {
    LiftResult res;
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) { res.unsupported.push_back("no-section"); return res; }
    const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(va - pe.image_base - sec->va);

    // .pdata 的 size 含尾部 int3/nop 对齐填充；剥掉填充后再判定流程是否收尾
    uint32_t effSize = size;
    while (effSize > 0 && (code[effSize - 1] == 0xCC || code[effSize - 1] == 0x90)) --effSize;
    if (effSize == 0) { res.unsupported.push_back("all-padding"); return res; }

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // 预扫：线性解码能落到的指令起始地址（分支只能跳进这个集合，否则标签不存在）
    std::unordered_set<uint64_t> labelSet;
    {
        size_t p = 0;
        ZydisDecodedInstruction i2;
        ZydisDecodedOperand o2[ZYDIS_MAX_OPERAND_COUNT];
        while (p < effSize) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + p, effSize - p, &i2, o2))) break;
            labelSet.insert(va + p);
            p += i2.length;
        }
    }

    Emit e;
    e.flags = flags;
    e.out << "void sub_" << std::hex << va << std::dec << "(X64Ctx* ctx) {\n"
          << "  MEW_SET_CUR_FN(ctx, 0x" << hexStr(va) << "ULL);\n";

    size_t off = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    while (off < effSize) {
        uint64_t rip = va + off;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, effSize - off, &insn, ops))) {
            if (flags & LIFT_STUB_UNKNOWN) {
                e.stubbed = true;
                e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"decode-fail\");\n";
                e.count++;
            } else {
                e.unsupported.push_back("decode-fail");
            }
            break;
        }
        uint64_t next_rip = rip + insn.length;
        const char* m = ZydisMnemonicGetString(insn.mnemonic);
        std::string mn = m ? m : "?";
        e.count++;

        for (uint16_t oi = 0; oi < insn.operand_count; ++oi) {
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.usesMemory = true;
                if (oi == 0) e.writesMemory = true;
            }
        }
        if (e.count == 1) {
            if (mn == "push" ||
                (mn == "sub" && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RSP) ||
                (mn == "mov" && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY)) {
                e.hasPrologue = true;
            }
        }

        e.out << "L_" << std::hex << rip << std::dec << ": ;\n";

        bool xmmOp = false;
        for (uint16_t oi = 0; oi < insn.operand_count; ++oi)
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_REGISTER && xmmId(ops[oi].reg.value) >= 0) xmmOp = true;

        const bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
        const std::string setcc = ccSuffix(mn, "set");
        const std::string cmovcc = ccSuffix(mn, "cmov");

        if (tryEmitSse(e, pe, mn, insn, ops, next_rip)) {
            /* SSE 已处理 */
        } else if (mn == "nop" || mn == "int3" || mn == "endbr64" || mn == "pause") {
            /* no-op */
        } else if (mn == "ret") {
            e.out << "  MEW_RET_TRACE(ctx);\n  ctx->rsp += 8; return;\n";
        } else if (mn == "leave") {
            e.out << "  write_reg(ctx,4,read_reg(ctx,5,8),8); write_reg(ctx,5,mem_read<uint64_t>(ctx,ctx->rsp),8); ctx->rsp += 8;\n";
        } else if (mn == "push") {
            e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, "
                  << valExpr(pe, insn, ops[0], next_rip, e) << ");\n";
        } else if (mn == "pop") {
            storeExpr(pe, insn, ops[0], "mem_read<uint64_t>(ctx,ctx->rsp)", next_rip, 8, e);
            e.out << "  ctx->rsp += 8;\n";
        } else if (mn == "mov" || mn == "movzx" || mn == "movsx" || mn == "movsxd" || mn == "movd" || mn == "movq") {
            std::string v = valExpr(pe, insn, ops[1], next_rip, e);
            if (mn == "movzx") {
                unsigned bits = ops[1].size;
                if (bits < 64) {
                    std::ostringstream t;
                    t << std::hex << ((1ULL << bits) - 1);
                    v = "(" + v + " & 0x" + t.str() + "ULL)";
                }
            } else if (mn == "movsx" || mn == "movsxd") {
                v = "(uint64_t)(int64_t)(int" + std::to_string(ops[1].size) + "_t)(" + v + ")";
            }
            storeExpr(pe, insn, ops[0], v, next_rip, ops[0].size / 8, e);
        } else if (mn == "lea") {
            storeExpr(pe, insn, ops[0], addrExpr(pe, ops[1], next_rip, e), next_rip, ops[0].size / 8, e);
        } else if (mn == "add" || mn == "sub" || mn == "cmp" || mn == "and" || mn == "or" ||
                   mn == "xor" || mn == "test") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = valExpr(pe, insn, ops[1], next_rip, e);
            int w = ops[0].size / 8;
            std::string call;
            if (mn == "add") call = "add_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            else if (mn == "sub" || mn == "cmp") call = "sub_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            else {
                std::string opx = (mn == "and" || mn == "test") ? "&" : (mn == "or") ? "|" : "^";
                call = "logic_flags(ctx,(" + a + " " + opx + " " + b + ")," + std::to_string(w) + ")";
            }
            if (mn == "cmp" || mn == "test") e.out << "  (void)" << call << ";\n";
            else storeExpr(pe, insn, ops[0], call, next_rip, w, e);
        } else if (mn == "inc" || mn == "dec") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            int w = ops[0].size / 8;
            std::string call = (mn == "inc") ? "add_flags(ctx," + a + ",1ULL," + std::to_string(w) + ")"
                                             : "sub_flags(ctx," + a + ",1ULL," + std::to_string(w) + ")";
            storeExpr(pe, insn, ops[0], call, next_rip, w, e);
        } else if (mn == "neg") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            int w = ops[0].size / 8;
            storeExpr(pe, insn, ops[0], "sub_flags(ctx,0ULL," + a + "," + std::to_string(w) + ")", next_rip, w, e);
        } else if (mn == "not") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            storeExpr(pe, insn, ops[0], "(~" + a + ")", next_rip, ops[0].size / 8, e);
        } else if (mn == "cdqe" || mn == "cwde" || mn == "cbw" || mn == "cdq" || mn == "cqo" || mn == "cwd") {
            if (mn == "cdqe") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int32_t)read_reg(ctx,0,4),8);\n";
            else if (mn == "cwde") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int16_t)read_reg(ctx,0,2),4);\n";
            else if (mn == "cbw") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int8_t)read_reg(ctx,0,1),2);\n";
            else if (mn == "cdq") e.out << "  write_reg(ctx,2,(uint64_t)(int64_t)((int64_t)(int32_t)read_reg(ctx,0,4) >> 31),4);\n";
            else e.out << "  write_reg(ctx,2,(uint64_t)((int64_t)read_reg(ctx,0,8) >> 63),8);\n";
        } else if (mn == "imul") {
            // 注意：不能只信 insn.operand_count。实测 49 0F AF D8（imul rbx,r8 两操作数）
            // 会被报成 3 个操作数，第 3 个是 UNUSED —— 旧代码走进 3 操作数分支后
            // 把它当成"立即数 0"，生成 rbx = r8 * 0，_calloc_base 于是申请 1 字节
            // （PTD 要 0x3C8），后续堆块全部重叠、CRT 初始化器 abort。
            // Zydis 会把隐式写出的 RFLAGS 也放进操作数数组（REGISTER 类型但既不是
            // GPR 也不是 XMM），它的 gprId/xmmId 都是 -1、valExpr 退化成 "0"。
            // 所以这里只接受"真实可读写"的操作数。
            const auto imulOpUsable = [](const ZydisDecodedOperand& o) {
                if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) return true;
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) return true;
                if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) return gprId(o.reg.value) >= 0 || xmmId(o.reg.value) >= 0;
                return false;
            };
            int opn = (int)insn.operand_count;
            while (opn > 1 && !imulOpUsable(ops[opn - 1])) --opn;
            if (opn <= 1) {
                e.out << "  { int64_t x=(int64_t)read_reg(ctx,0,8), y=(int64_t)"
                      << valExpr(pe, insn, ops[0], next_rip, e) << "; __int128 p=(__int128)x*y;"
                         " write_reg(ctx,0,(uint64_t)p,8); write_reg(ctx,2,(uint64_t)(p>>64),8); }\n";
            } else if (opn == 2) {
                int id = gprId(ops[0].reg.value);
                int w = ops[0].size / 8;
                e.out << "  write_reg(ctx," << id << ",(uint64_t)((int64_t)read_reg(ctx," << id << "," << w
                      << ") * (int64_t)" << valExpr(pe, insn, ops[1], next_rip, e) << ")," << w << ");\n";
            } else {
                int id = gprId(ops[0].reg.value);
                int w = ops[0].size / 8;
                e.out << "  write_reg(ctx," << id << ",(uint64_t)((int64_t)"
                      << valExpr(pe, insn, ops[1], next_rip, e) << " * (int64_t)"
                      << valExpr(pe, insn, ops[2], next_rip, e) << ")," << w << ");\n";
            }
        } else if (mn == "shl" || mn == "shr" || mn == "sar") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = (insn.operand_count > 1) ? valExpr(pe, insn, ops[1], next_rip, e) : "1ULL";
            int w = ops[0].size / 8;
            std::string shift = (mn == "shl") ? "<<" : ">>";
            if (mn == "sar") {
                storeExpr(pe, insn, ops[0],
                          "(uint64_t)((int64_t)(" + a + ") >> (" + b + " & 63))", next_rip, w, e);
            } else {
                storeExpr(pe, insn, ops[0], "((" + a + ") " + shift + " (" + b + " & 63))", next_rip, w, e);
            }
        } else if (mn == "rol" || mn == "ror") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = (insn.operand_count > 1) ? valExpr(pe, insn, ops[1], next_rip, e) : "1ULL";
            int w = ops[0].size / 8;
            int bits = w * 8;
            std::string fn = (mn == "rol") ? "rotl" : "rotr";
            storeExpr(pe, insn, ops[0], std::string(fn) + "<uint64_t>(" + a + "," + b + ") & " +
                                     std::to_string(bits == 64 ? ~0ULL : ((1ULL << bits) - 1)) + "ULL",
                      next_rip, w, e);
        } else if (mn == "int") {
            uint64_t imm = (insn.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                         ? (uint64_t)ops[0].imm.value.u : 3;
            if (imm == 3) {
                /* int3：断点填充，按 nop 处理 */
            } else {
                /* int 0x29 = __fastfail（CRT 致命路径），int 0x2c = 断言。
                   旧实现当占位跳过，掩盖了真正的失败原因；现在显式报告。 */
                e.out << "  MEW_FASTFAIL(ctx, 0x" << hexStr(rip) << "ULL, " << imm << ");\n";
            }
        } else if (mn == "bt" || mn == "btc" || mn == "btr" || mn == "bts") {
            int w = ops[0].size / 8;
            int nbits = w * 8;
            e.out << "  { uint64_t b=" << valExpr(pe, insn, ops[0], next_rip, e)
                  << "; uint64_t ii=(" << valExpr(pe, insn, ops[1], next_rip, e) << ") & " << (nbits - 1) << ";\n"
                     "    ctx->cf = ((b >> ii) & 1ULL) != 0;\n";
            if (mn == "bts") e.out << "    b |= (1ULL << ii);\n";
            else if (mn == "btr") e.out << "    b &= ~(1ULL << ii);\n";
            else if (mn == "btc") e.out << "    b ^= (1ULL << ii);\n";
            if (mn != "bt") storeExpr(pe, insn, ops[0], "b", next_rip, w, e);
            e.out << "  }\n";
        } else if (mn == "bsf" || mn == "bsr" || mn == "tzcnt" || mn == "lzcnt" || mn == "popcnt") {
            int w = ops[0].size / 8;
            std::string src = valExpr(pe, insn, ops[1], next_rip, e);
            // 注意 bsr 与 lzcnt 的语义相反：
            //   bsr  -> 最高置位 bit 的下标（63 - clz）
            //   lzcnt-> 前导零个数（clz）
            // 以前把两者合成 x64_clz，直接让 _Hash 的桶上限从 2^59 变成 2^4。
            std::string fn = (mn == "bsf" || mn == "tzcnt") ? "x64_ctz"
                           : (mn == "bsr") ? "x64_bsr"
                           : (mn == "lzcnt") ? "x64_clz" : "x64_popcnt";
            storeExpr(pe, insn, ops[0], fn + "(" + src + ", " + std::to_string(w * 8) + ")", next_rip, w, e);
            if (mn == "bsf" || mn == "bsr") {
                e.out << "  (void)sub_flags(ctx," << src << ",0ULL," << w << ");\n";
            }
        } else if (mn == "cmpxchg") {
            int w = ops[0].size / 8;
            std::string dst = valExpr(pe, insn, ops[0], next_rip, e);
            std::string srcv = valExpr(pe, insn, ops[1], next_rip, e);
            uint64_t mask = w >= 8 ? ~0ULL : ((1ULL << (w * 8)) - 1);
            e.out << "  { uint64_t d=" << dst << ", s=" << srcv
                  << ", acc=read_reg(ctx,0," << w << ") & " << mask << "ULL;\n"
                     "    (void)sub_flags(ctx,acc,d," << w << ");\n"
                     "    if (ctx->zf) { d = s; } else { write_reg(ctx,0,d," << w << "); }\n";
            storeExpr(pe, insn, ops[0], "d", next_rip, w, e);
            e.out << "  }\n";
        } else if (mn == "xadd") {
            int w = ops[0].size / 8;
            std::string dst = valExpr(pe, insn, ops[0], next_rip, e);
            std::string srcv = valExpr(pe, insn, ops[1], next_rip, e);
            e.out << "  { uint64_t d=" << dst << ", s=" << srcv << ";\n";
            storeExpr(pe, insn, ops[1], "d", next_rip, w, e);
            e.out << "    uint64_t r=add_flags(ctx,d,s," << w << ");\n";
            storeExpr(pe, insn, ops[0], "r", next_rip, w, e);
            e.out << "  }\n";
        } else if (!xmmOp && (mn == "stosb" || mn == "stosw" || mn == "stosd" || mn == "stosq" ||
                   mn == "movsb" || mn == "movsw" || mn == "movsd" || mn == "movsq" ||
                   mn == "lodsb" || mn == "lodsw" || mn == "lodsd" || mn == "lodsq" ||
                   mn == "scasb" || mn == "scasw" || mn == "scasd" || mn == "scasq" ||
                   mn == "cmpsb" || mn == "cmpsw" || mn == "cmpsd" || mn == "cmpsq")) {
            const char* base = mn.c_str();
            char op = base[0];
            char sz = mn.back();
            int bytes = (sz == 'b') ? 1 : (sz == 'w') ? 2 : (sz == 'd') ? 4 : 8;
            int rep = (insn.attributes & ZYDIS_ATTRIB_HAS_REP) ? 1 : 0;
            int repne = (insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) ? 1 : 0;
            if (op == 's' && mn.rfind("stos", 0) == 0) e.out << "  x64_stos(ctx," << bytes << "," << rep << ");\n";
            else if (op == 'm') e.out << "  x64_movs(ctx," << bytes << "," << rep << ");\n";
            else if (op == 'l') e.out << "  x64_lods(ctx," << bytes << "," << rep << ");\n";
            else if (mn.rfind("scas", 0) == 0) e.out << "  x64_scas(ctx," << bytes << "," << rep << "," << repne << ");\n";
            else e.out << "  x64_cmps(ctx," << bytes << "," << rep << "," << repne << ");\n";
        } else if (mn == "cld") {
            e.out << "  ctx->df = false;\n";
        } else if (mn == "std") {
            e.out << "  ctx->df = true;\n";
        } else if (mn == "clc") {
            e.out << "  ctx->cf = false;\n";
        } else if (mn == "stc") {
            e.out << "  ctx->cf = true;\n";
        } else if (mn == "cmc") {
            e.out << "  ctx->cf = !ctx->cf;\n";
        } else if (mn == "xchg") {
            std::string v0 = valExpr(pe, insn, ops[0], next_rip, e);
            std::string v1 = valExpr(pe, insn, ops[1], next_rip, e);
            e.out << "  { uint64_t t0=" << v0 << "; uint64_t t1=" << v1 << ";\n";
            storeExpr(pe, insn, ops[0], "t1", next_rip, ops[0].size / 8, e);
            storeExpr(pe, insn, ops[1], "t0", next_rip, ops[1].size / 8, e);
            e.out << "  }\n";
        } else if (mn == "cpuid") {
            e.out << "  { uint32_t a=(uint32_t)read_reg(ctx,0,4), b=0, c=(uint32_t)read_reg(ctx,1,4), d=0;\n"
                     "    x64_cpuid(a, c, &a, &b, &c, &d);\n"
                     "    write_reg(ctx,0,a,4); write_reg(ctx,3,b,4); write_reg(ctx,2,c,4); write_reg(ctx,1,d,4); }\n";
        } else if (mn == "xgetbv") {
            e.out << "  { uint32_t a=7, d=0; write_reg(ctx,0,a,4); write_reg(ctx,2,d,4); }\n";
        } else if (mn == "xsetbv") {
            /* 忽略：模拟器不管理 XCR */
        } else if (mn == "rdtsc") {
            e.out << "  { uint64_t t=x64_rdtsc(); write_reg(ctx,0,t,4); write_reg(ctx,2,(t>>32),4); }\n";
        } else if (mn == "bswap") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            e.out << "  write_reg(ctx," << gprId(ops[0].reg.value) << ",bswap64(" << a << "),8);\n";
        } else if (mn == "jmp") {
            if (tryEmitCfg(e, pe, mn, ops[0], next_rip)) {
                /* CFG dispatch 已处理 */
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t >= va && t < va + effSize) {
                    if (labelSet.count(t)) {
                        e.out << "  goto L_" << hexStr(t) << ";\n";
                    } else if (flags & LIFT_FRAGMENT) {
                        if (g_needed_entries) g_needed_entries->insert(t);
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                    } else if (flags & LIFT_STUB_UNKNOWN) {
                        e.stubbed = true;
                        e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-missing\");\n";
                    } else {
                        e.unsupported.push_back("jump-missing");
                        break;
                    }
                } else if (flags & LIFT_FRAGMENT) {
                    if (g_needed_entries) g_needed_entries->insert(t);
                    e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                } else if (flags & LIFT_TAIL_JUMP) {
                    // 尾调用：不压模拟返回地址，直接跳/返回
                    if (pe.hasFunction(t)) {
                        e.out << "  return sub_" << hexStr(t) << "(ctx);\n";
                    } else if (const ImportSlot* im = resolveIatThunk(pe, t)) {
                        e.iatCall = true;
                        // jmp [IAT] 是尾调用：本函数的 ret 由垫片代劳，必须把调用方压入的
                        // 返回地址弹掉。否则每个导入跳板都漏 8 字节，逐层累积后
                        // MSVC stack cookie（xor rsp）校验失败 -> __fastfail(2)。
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8; return;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                    }
                } else { e.unsupported.push_back("jump-out-of-func"); break; }
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ops[0].mem.index != ZYDIS_REGISTER_NONE) {
                // switch 跳转表：jmp qword ptr [index*scale + table]
                int64_t disp = ops[0].mem.disp.has_displacement ? (int64_t)ops[0].mem.disp.value : 0;
                uint64_t tbl = 0;
                if (ops[0].mem.base == ZYDIS_REGISTER_RIP) tbl = next_rip + disp;
                else if (ops[0].mem.base == ZYDIS_REGISTER_NONE) tbl = (uint64_t)(uint32_t)disp;
                int idx_reg = gprId(ops[0].mem.index);
                int scale = (int)ops[0].mem.scale;
                bool expanded = false;
                if (tbl && idx_reg >= 0 && (scale == 8 || scale == 4) && effSize < 0x10000) {
                    std::vector<std::pair<uint64_t, uint64_t>> table;  // (index, target)
                    bool all_in = true;
                    for (int k = 0; k < 256; ++k) {
                        uint64_t raw = 0;
                        if (!readGuestQword(pe, tbl + (uint64_t)k * scale, &raw)) { break; }
                        if (!raw) continue;
                        // 表项可能是原始 VA，也可能已被重定位；两种都接受
                        uint64_t t = raw;
                        if (t > (1ULL << 47)) t = (uint64_t)((int64_t)raw - pe.image_base) + pe.image_base;  // no-op 保护
                        if (t < va || t >= va + effSize) { all_in = false; break; }
                        if (!labelSet.count(t)) { all_in = false; break; }
                        table.push_back({(uint64_t)k, t});
                        if (table.size() >= 128) break;
                    }
                    if (all_in && table.size() >= 2) {
                        e.out << "  { uint64_t ix = read_reg(ctx," << idx_reg << ",8);\n"
                                 "    switch (ix) {\n";
                        for (const auto& kv : table)
                            e.out << "      case " << kv.first << "ULL: goto L_" << hexStr(kv.second) << ";\n";
                        e.out << "      default: UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-table-oor\");\n"
                                 "    }\n"
                                 "  }\n";
                        expanded = true;
                    }
                }
                if (!expanded) {
                    if (flags & LIFT_TAIL_JUMP) {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx); return;\n";
                    } else {
                        e.unsupported.push_back("jmp-indirect");
                    }
                }
            } else if (flags & LIFT_TAIL_JUMP) {
                if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t slot = next_rip + (int64_t)ops[0].mem.disp.value;
                    if (const ImportSlot* im = pe.importBySlot(slot)) {
                        e.iatCall = true;
                        // jmp [IAT] 是尾调用：本函数的 ret 由垫片代劳，必须把调用方压入的
                        // 返回地址弹掉。否则每个导入跳板都漏 8 字节，逐层累积后
                        // MSVC stack cookie（xor rsp）校验失败 -> __fastfail(2)。
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8; return;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(mem_read<uint64_t>(ctx,0x" << hexStr(slot) << "ULL), ctx); return;\n";
                    }
                } else {
                    e.indirectCall = true;
                    e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx); return;\n";
                }
            } else {
                e.unsupported.push_back("jmp-indirect");
            }
        } else if (mn == "jrcxz" || mn == "jecxz" || mn == "jcxz") {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            std::string cond = (mn == "jrcxz") ? "(read_reg(ctx,1,8) == 0)"
                             : (mn == "jecxz") ? "(read_reg(ctx,1,4) == 0)"
                                               : "(read_reg(ctx,1,2) == 0)";
            if (t >= va && t < va + effSize && labelSet.count(t)) {
                e.out << "  if (" << cond << ") goto L_" << hexStr(t) << ";\n";
            } else if (flags & LIFT_STUB_UNKNOWN) {
                e.stubbed = true;
                e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"" << mn << "\");\n";
            } else {
                e.unsupported.push_back(mn);
            }
        } else if (isJcc) {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            std::string cond = ccExpr(mn);
            if (t >= va && t < va + effSize && !labelSet.count(t)) {
                if (flags & LIFT_FRAGMENT) {
                    if (g_needed_entries) g_needed_entries->insert(t);
                    e.out << "  if (" << cond << ") { dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return; }\n";
                } else if (flags & LIFT_STUB_UNKNOWN) {
                    e.stubbed = true;
                    e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-missing\");\n";
                } else {
                    e.unsupported.push_back("jump-missing");
                }
                off += insn.length;
                continue;
            }
            if (t < va || t >= va + effSize) {
                if ((flags & LIFT_FRAGMENT) && !cond.empty()) {
                    if (g_needed_entries) g_needed_entries->insert(t);
                    e.out << "  if (" << cond << ") { dispatch_indirect(0x" << hexStr(t)
                          << "ULL, ctx); return; }\n";
                    off += insn.length;
                    continue;
                }
                if ((flags & LIFT_TAIL_JUMP) && pe.hasFunction(t)) {
                    if (cond.empty()) { e.unsupported.push_back(mn); break; }
                    // 目标在另一块：cond 成立即尾跳进冷片段
                    e.out << "  if (" << cond << ") return sub_" << hexStr(t) << "(ctx);\n";
                    off += insn.length;
                    continue;
                }
                e.unsupported.push_back("jump-out-of-func"); break;
            }
            if (cond.empty()) { e.unsupported.push_back(mn); break; }
            e.out << "  if (" << cond << ") goto L_" << std::hex << t << std::dec << ";\n";
        } else if (!setcc.empty()) {
            storeExpr(pe, insn, ops[0], "((uint64_t)(" + setcc + "))", next_rip, 1, e);
        } else if (!cmovcc.empty()) {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = valExpr(pe, insn, ops[1], next_rip, e);
            storeExpr(pe, insn, ops[0], "((" + cmovcc + ") ? " + b + " : " + a + ")", next_rip, ops[0].size / 8, e);
        } else if (mn == "call") {
            e.hasCall = true;
            if (tryEmitCfg(e, pe, mn, ops[0], next_rip)) {
                /* CFG dispatch 已处理 */
            } else if (!(flags & LIFT_ALLOW_CALL)) {
                e.unsupported.push_back("call");
            } else {
                const auto pushRet = [&]() {
                    e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, 0x"
                          << hexStr(next_rip) << "ULL);\n";
                };
                if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                    pushRet();
                    if (pe.hasFunction(t)) {
                        e.directCalls++;
                        // 直接调用也要做 ABI 守卫：只测 dispatch 会漏掉直接调用的 rsp 失衡，
                        // 而 MSVC 的 stack cookie 校验对 rsp 极其敏感（失配即 __fastfail(2)）。
                        e.out << "  { AbiSnapshot _s = abi_snap(ctx); uint64_t _c = cur_fn_va();\n"
                                 "    sub_" << hexStr(t) << "(ctx);\n"
                                 "    if (mew_abi_guard_on() || mew_stack_repair_on())\n"
                                 "      abi_guard_after_call(ctx, _s, 0x" << hexStr(t) << "ULL, _c, 8); }\n";
                    } else if (const ImportSlot* im = resolveIatThunk(pe, t)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx, true);\n";
                    }
                } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t slot = next_rip + (int64_t)ops[0].mem.disp.value;
                    pushRet();
                    if (const ImportSlot* im = pe.importBySlot(slot)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(mem_read<uint64_t>(ctx,0x" << hexStr(slot) << "ULL), ctx, true);\n";
                    }
                } else {
                    pushRet();
                    e.indirectCall = true;
                    e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx, true);\n";
                }
            }
        } else if (flags & LIFT_STUB_UNKNOWN) {
            e.stubbed = true;
            if (g_stub_hist) (*g_stub_hist)[mn]++;
            e.stubMnems.push_back(mn);
            e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"" << mn << "\");\n";
        } else {
            e.unsupported.push_back(mn);
        }

        if (!e.unsupported.empty()) break;
        off += insn.length;
    }

    // 末尾必须收尾：ret / jmp / 已 unsupported；否则执行会流到函数外（真机进入下一函数字节或 int3）
    if (e.unsupported.empty()) {
        bool terminated = false;
        {
            const char* m2 = ZydisMnemonicGetString(insn.mnemonic);
            std::string last = m2 ? m2 : "?";
            res.lastMnemonic = last;
            terminated = (last == "ret" || last == "jmp");
        }
        if (!terminated) e.fallsOffEnd = true;
    }
    if (e.unsupported.empty()) e.out << "}\n";
    res.ok = e.unsupported.empty() && e.count > 0;
    res.code = e.out.str();
    res.unsupported = e.unsupported;
    res.insnCount = e.count;
    res.usesRipData = e.usesRipData;
    res.hasCall = e.hasCall;
    res.usesMemory = e.usesMemory;
    res.writesMemory = e.writesMemory;
    res.hasPrologue = e.hasPrologue;
    res.usesNonStackMem = e.usesNonStackMem;
    res.fallsOffEnd = e.fallsOffEnd;
    res.ptrArgMask = e.ptrArgMask;
    res.badMemBase = e.badMemBase;
    res.directCalls = e.directCalls;
    res.indirectCall = e.indirectCall;
    res.iatCall = e.iatCall;
    res.stubbed = e.stubbed;
    res.stubMnems = e.stubMnems;
    return res;
}


// 可达性判定：从入口走遍所有路径，任一路径流出 [va, va+size) 就返回 false
bool controlFlowClosed(const PeImage& pe, uint64_t va, uint32_t size) {
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) return false;
    const uint8_t* base = pe.data.data() + sec->raw;
    const uint32_t rva0 = (uint32_t)(va - pe.image_base - sec->va);
    // 剥掉尾部填充
    uint32_t eff = size;
    while (eff > 0) {
        uint8_t b = 0;
        uint32_t o = va + eff - 1 - (uint32_t)pe.image_base - sec->va;
        if (o < sec->rawsize) b = base[o]; else break;
        if (b == 0xCC || b == 0x90) --eff; else break;
    }
    if (eff == 0) return false;
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    std::vector<uint64_t> work{va};
    std::vector<uint64_t> seen;
    while (!work.empty()) {
        uint64_t cur = work.back(); work.pop_back();
        for (uint64_t v : seen) if (v == cur) goto next_item;
        seen.push_back(cur);
        for (;;) {
            if (cur < va || cur >= va + eff) return false;
            uint32_t off = (uint32_t)(cur - va) + rva0;
            if (off >= sec->rawsize || (uint32_t)(cur - va) >= eff) return false;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, base + off,
                    sec->rawsize - off < eff - (uint32_t)(cur - va) ? sec->rawsize - off : eff - (uint32_t)(cur - va),
                    &insn, ops))) return false;
            uint64_t next_rip = cur + insn.length;
            const char* m = ZydisMnemonicGetString(insn.mnemonic);
            std::string mn = m ? m : "?";
            if (mn == "ret") break;
            if (mn == "jmp") {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                if (t < va || t >= va + eff) return false;
                work.push_back(t);
                break;
            }
            bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
            if (isJcc) {
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + eff) return false;
                work.push_back(t);
            } else if (mn == "call") {
                return false;
            }
            cur = next_rip;
            if (cur >= va + eff) return false;  // 非收尾指令淌出函数
        }
    next_item:;
    }
    return true;
}


// 寄存器输入分析：函数只能读取“我们提供的”寄存器（rcx/rdx/r8/r9 + rsp），
// 读取未初始化寄存器（rbx/rsi/rdi/r12-r15/rax/r10/r11/rbp）说明它需要调用方上下文，阶段 2 不可独立调用。
static int gprIdxOf(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_RCX: return 1;
        case ZYDIS_REGISTER_RDX: return 2;
        case ZYDIS_REGISTER_RBX: return 3;
        case ZYDIS_REGISTER_RSP: return 4;
        case ZYDIS_REGISTER_RBP: return 5;
        case ZYDIS_REGISTER_RSI: return 6;
        case ZYDIS_REGISTER_RDI: return 7;
        case ZYDIS_REGISTER_R8:  return 8;
        case ZYDIS_REGISTER_R9:  return 9;
        case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15: return 15;
        default: return -1;
    }
}

static bool writesOnlyOperand0(const std::string& mn) {
    static const char* k[] = {"mov", "movzx", "movsx", "movsxd", "movd", "movq", "lea", "pop",
                              "setcc", "cbw", "cwde", "cdqe", "cdq", "cqo", "cwd", "bswap"};
    for (const char* x : k) if (mn == x) return true;
    return false;
}

bool registerInputsOk(const PeImage& pe, uint64_t va, uint32_t size) {
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) return false;
    const uint8_t* base = pe.data.data() + sec->raw;
    const uint32_t rva0 = (uint32_t)(va - pe.image_base - sec->va);
    uint32_t eff = size;
    while (eff > 0) {
        uint32_t o = va + eff - 1 - (uint32_t)pe.image_base - sec->va;
        if (o >= sec->rawsize) break;
        uint8_t b = base[o];
        if (b == 0xCC || b == 0x90) --eff; else break;
    }
    if (eff == 0) return false;

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    // 位=1 表示“该寄存器当前值未知（来自调用方或未初始化）”
    uint16_t kInit = (uint16_t)(0xFFFFu & ~((1u << 1) | (1u << 2) | (1u << 8) | (1u << 9) | (1u << 4)));
    kInit = (uint16_t)kInit;

    // 工作项：(地址, 进入时的已初始化掩码)
    std::vector<std::pair<uint64_t, uint16_t>> work{{va, kInit}};
    std::vector<std::pair<uint64_t, uint16_t>> seen;
    while (!work.empty()) {
        std::pair<uint64_t, uint16_t> item = work.back(); work.pop_back();
        uint64_t cur = item.first;
        uint16_t init = item.second;
        bool merged = false;
        for (auto& sv : seen) {
            if (sv.first == cur) {
                // 未知掩码：任一路径未知即视为未知（并集，保守）
                uint16_t uni = (uint16_t)(sv.second | init);
                if (uni == sv.second) { merged = true; break; }
                sv.second = uni;
                init = uni;
                break;
            }
        }
        if (merged) continue;
        bool isNew = true;
        for (auto& sv : seen) if (sv.first == cur) { isNew = false; break; }
        if (isNew) seen.push_back({cur, init});

        for (;;) {
            if (cur < va || cur >= va + eff) return false;
            uint32_t rel = (uint32_t)(cur - va);
            uint32_t off = rel + rva0;
            if (off >= sec->rawsize) return false;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            uint32_t avail = eff - rel;
            if (sec->rawsize - off < avail) avail = sec->rawsize - off;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, base + off, avail, &insn, ops))) return false;
            uint64_t next_rip = cur + insn.length;
            const char* m = ZydisMnemonicGetString(insn.mnemonic);
            std::string mn = m ? m : "?";
            const bool wo0 = writesOnlyOperand0(mn);
            const bool xorSelf = (mn == "xor" || mn == "sub") &&
                insn.operand_count >= 2 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ops[0].reg.value == ops[1].reg.value;
            // ---- 污点检查 ----
            bool srcUnknown = false;
            for (uint16_t oi = 0; oi < insn.operand_count; ++oi) {
                if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    int gb = gprIdxOf(ops[oi].mem.base);
                    int gx = gprIdxOf(ops[oi].mem.index);
                    if (gb >= 0 && (init & (1u << gb))) return false;   // 未知值当地址 -> 会崩
                    if (gx >= 0 && (init & (1u << gx))) return false;
                    continue;
                }
                if (ops[oi].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
                int gi = gprIdxOf(ops[oi].reg.value);
                if (gi < 0) continue;
                bool reads = (oi >= 1) || !(wo0 || xorSelf);
                if (reads && (init & (1u << gi))) srcUnknown = true;
            }
            if (insn.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                int gd = gprIdxOf(ops[0].reg.value);
                if (gd >= 0) {
                    bool destReads = !(wo0 || xorSelf);
                    bool unk = srcUnknown || (destReads && (init & (1u << gd)));
                    if (xorSelf) unk = false;
                    if (unk) init |= (uint16_t)(1u << gd); else init &= (uint16_t)~(1u << gd);
                }
            }
            if (mn == "ret") break;
            if (mn == "jmp") {
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + eff) return false;
                work.push_back({t, init});
                break;
            }
            bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
            if (isJcc) {
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + eff) return false;
                work.push_back({t, init});
            }
            cur = next_rip;
            if (cur >= va + eff) return false;
        }
    }
    return true;
}

bool pickPureFunction(const PeImage& pe, size_t minSize, size_t maxSize,
                      std::vector<std::pair<uint64_t, uint32_t>>& out,
                      std::vector<uint32_t>* masks) {
    out.clear();
    if (masks) masks->clear();
    size_t nSize = 0, nLift = 0, nNoCall = 0, nNoRip = 0, nFramed = 0, nClosed = 0;
    bool capped = false;
    for (const auto& fn : pe.functions) {
        if (fn.second < minSize || fn.second > maxSize) continue;
        ++nSize;
        LiftResult r = liftFunction(pe, fn.first, fn.second);
        if (!r.ok) continue;
        ++nLift;
        if (r.hasCall) continue;
        ++nNoCall;
        if (r.usesRipData) continue;
        ++nNoRip;
        // 纯栈访问要求有正规栈帧；用到参数指针的则无需栈帧
        if (r.usesMemory && r.ptrArgMask == 0 && !r.hasPrologue) continue;
        ++nFramed;
        if (!controlFlowClosed(pe, fn.first, fn.second)) continue;
        if (!registerInputsOk(pe, fn.first, fn.second)) continue;
        ++nClosed;
        out.push_back(fn);
        if (masks) masks->push_back(r.ptrArgMask);
        if (out.size() >= 8) { capped = true; break; }
    }
    fprintf(stderr, "[funnel] size=%zu lift_ok=%zu no_call=%zu no_ripdata=%zu framed=%zu cf_closed=%zu capped=%d\n",
            nSize, nLift, nNoCall, nNoRip, nFramed, nClosed, (int)capped);
    return !out.empty();
}

// ---------------- 阶段 3：分片生成 ----------------
namespace {

std::string hexva(uint64_t v) { std::ostringstream o; o << std::hex << v; return o.str(); }

}  // namespace

bool pickNestedCandidate(const PeImage& pe, NestedCand* out,
                         std::vector<std::pair<uint64_t, uint32_t>>* closure,
                         size_t skip) {
    struct Info { bool ok; bool okNoStub; int direct; bool ind; bool iat; bool rip; uint32_t size;
                  uint32_t ptrMask; bool nonStackMem; bool prologue; std::string last;
                  bool badBase; };
    std::unordered_map<uint64_t, Info> infos;
    infos.reserve(pe.functions.size() * 2);
    std::unordered_map<uint64_t, uint32_t> sizes;
    for (const auto& fn : pe.functions) sizes[fn.first] = fn.second;

    for (const auto& fn : pe.functions) {
        LiftResult r = liftFunctionEx(pe, fn.first, fn.second,
                                      LIFT_ALLOW_CALL | LIFT_TAIL_JUMP);
        Info i;
        i.okNoStub = r.ok && !r.stubbed;
        i.ok = r.ok;
        i.direct = r.directCalls;
        i.ind = r.indirectCall;
        i.iat = r.iatCall;
        i.rip = r.usesRipData;
        i.size = fn.second;
        i.ptrMask = r.ptrArgMask;
        i.nonStackMem = r.usesNonStackMem;
        i.prologue = r.hasPrologue;
        i.last = r.lastMnemonic;
        i.badBase = r.badMemBase;
        infos[fn.first] = i;
    }

    auto collectTargets = [&](uint64_t va, uint32_t size, std::vector<uint64_t>& tgts) {
        const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
        if (!sec) return;
        const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(va - pe.image_base - sec->va);
        ZydisDecoder dec;
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        size_t off = 0;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        while (off < size) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, size - off, &insn, ops))) break;
            uint64_t next_rip = va + off + insn.length;
            // 直接调用 + 跨块尾跳（jmp/jcc 到本函数范围外）都算闭包边
            if ((insn.mnemonic == ZYDIS_MNEMONIC_CALL || insn.mnemonic == ZYDIS_MNEMONIC_JMP) &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + size) {
                    if (pe.hasFunction(t)) tgts.push_back(t);
                }
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       insn.mnemonic >= ZYDIS_MNEMONIC_JB && insn.mnemonic <= ZYDIS_MNEMONIC_JZ) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if ((t < va || t >= va + size) && pe.hasFunction(t)) tgts.push_back(t);
            }
            off += insn.length;
        }
    };

    size_t nRoot = 0, nRip = 0, nDirect = 0, tried = 0, matches = 0;
    struct Near { uint64_t va; int direct; size_t closure; size_t stubbed; bool iat, ind; };
    std::vector<Near> nears;

    for (int pass = 0; pass < 2; ++pass) {
    const bool strict = (pass == 0);
    for (const auto& fn : pe.functions) {
        auto it = infos.find(fn.first);
        if (it == infos.end()) continue;
        const Info& ri = it->second;
        ++nRoot;
        if (strict && (ri.ptrMask != 0 || ri.nonStackMem)) continue;
        if (!ri.ok || !ri.rip || ri.ind) continue;
        ++nRip;
        if (ri.iat) continue;
        if (ri.direct < 3 || ri.direct > 40) continue;
        ++nDirect;
        if (nears.size() < 8) ++tried;

        std::vector<uint64_t> work{fn.first}, seen{fn.first};
        size_t stubbed = 0;
        bool ok = true, hasIat = false, hasInd = false;
        while (!work.empty() && ok) {
            uint64_t cur = work.back(); work.pop_back();
            auto ci = infos.find(cur);
            if (ci == infos.end()) { ok = false; break; }
            if (!ci->second.ok) { ok = false; break; }
            if (!ci->second.okNoStub) ++stubbed;
            if (ci->second.iat) hasIat = true;
            if (ci->second.ind) hasInd = true;
            if (strict) {
                if (ci->second.ptrMask != 0 || ci->second.nonStackMem) { ok = false; break; }
                if (!ci->second.prologue || ci->second.last != "ret") { ok = false; break; }
                if (ci->second.badBase) { ok = false; break; }
            }
            auto sz = sizes.find(cur);
            if (sz == sizes.end()) { ok = false; break; }
            std::vector<uint64_t> tgts;
            collectTargets(cur, sz->second, tgts);
            for (uint64_t t : tgts) {
                bool dup = false;
                for (uint64_t v : seen) if (v == t) { dup = true; break; }
                if (!dup) {
                    seen.push_back(t); work.push_back(t);
                    if (seen.size() > 96) { ok = false; break; }
                }
            }
        }
        if (nears.size() < 8) nears.push_back({fn.first, ri.direct, seen.size(), stubbed, hasIat, hasInd});
        if (!ok) continue;
        if (hasIat || hasInd || stubbed > 0) continue;
        if (seen.size() > 96 || seen.size() < 4) continue;
        if (ri.size < 128) continue;
        if (matches++ < skip) continue;

        NestedCand c;
        c.va = fn.first;
        c.size = fn.second;
        c.directCalls = ri.direct;
        c.closure = seen.size();
        c.ptr_mask = ri.ptrMask;
        if (out) *out = c;
        if (closure) {
            closure->clear();
            for (uint64_t v : seen)
                for (const auto& f : pe.functions) if (f.first == v) { closure->push_back(f); break; }
            std::sort(closure->begin(), closure->end());
        }
        std::fprintf(stderr, "[nested] picked va=0x%llx direct=%d closure=%zu\n",
                     (unsigned long long)c.va, c.directCalls, c.closure);
        return true;
    }
    }
    std::fprintf(stderr, "[nested] none. scanned=%zu ok+rip=%zu direct-range=%zu\n",
                 nRoot, nRip, nDirect);
    for (const auto& n : nears)
        std::fprintf(stderr, "[nested] near va=0x%llx direct=%d closure=%zu stubbed=%zu iat=%d ind=%d\n",
                     (unsigned long long)n.va, n.direct, n.closure, n.stubbed,
                     (int)n.iat, (int)n.ind);
    return false;
}

void emitShardSet(const PeImage& pe, int shards, const std::string& outDir,
                  const std::vector<std::pair<uint64_t, uint32_t>>* only,
                  ShardStats* stats) {
    std::vector<std::pair<uint64_t, uint32_t>> list =
        only ? *only : pe.functions;
    std::sort(list.begin(), list.end());
    // 同一 VA 可能同时以「.pdata 登记长度」和「种子/片段长度」出现两次，
    // 直接生成会出现 sub_xxx 重复定义（shard_060/061 曾因此编译失败）。
    // 按 VA 去重，长度取较大者（片段覆盖不到尾巴时仍是完整函数）。
    {
        std::vector<std::pair<uint64_t, uint32_t>> uniq;
        uniq.reserve(list.size());
        for (const auto& p2 : list) {
            if (!uniq.empty() && uniq.back().first == p2.first) {
                if (p2.second > uniq.back().second) uniq.back().second = p2.second;
            } else {
                uniq.push_back(p2);
            }
        }
        list.swap(uniq);
    }
    if (shards < 1) shards = 1;

    std::vector<std::vector<std::pair<uint64_t, uint32_t>>> buckets((size_t)shards);
    for (size_t i = 0; i < list.size(); ++i)
        buckets[i * (size_t)shards / list.size()].push_back(list[i]);

    ShardStats st;
    st.total = list.size();
    st.shards = (size_t)shards;

    // all_decls.h：所有函数声明 + 垫片声明
    {
        std::ofstream o(outDir + "/all_decls.h");
        o << "#pragma once\n#include <cstdint>\n#include <cstdio>\n#include <cstdlib>\n"
             "#include \"x64_runtime.h\"\n#include \"x64_ops.h\"\n\n";
        for (const auto& fn : list)
            o << "void sub_" << hexva(fn.first) << "(X64Ctx* ctx);\n";
        o << "\n// IAT 垫片\n";
        for (const auto& im : pe.imports)
            o << "void shim_" << im.dll << "_" << im.name << "(X64Ctx* ctx);\n";
    }

    // 分片
    for (int si = 0; si < shards; ++si) {
        std::ostringstream name;
        name << outDir << "/shard_" << (si < 10 ? "00" : si < 100 ? "0" : "") << si << ".cpp";
        std::ofstream o(name.str());
        o << "// shard " << si << " / " << shards << "  functions=" << buckets[(size_t)si].size() << "\n"
             "#include \"all_decls.h\"\n\n";
        for (const auto& fn : buckets[(size_t)si]) {
            LiftResult r = liftFunctionEx(pe, fn.first, fn.second,
                                          LIFT_ALLOW_CALL | LIFT_TAIL_JUMP |
                                          LIFT_STUB_UNKNOWN | LIFT_FRAGMENT);
            // 带占位的函数一律整函数占位，绝不执行「半截」。
            // 半执行会跳过 epilogue：rsp 不平、rbx/rbp/rsi/rdi 停在被改写后的值，
            // 调用方随后 `add rbx,0x10; mov rax,[rbx]` 就会读到 [0x10] 并崩溃
            // （实测 __acrt_initialize_locks 清空 rbx 后撞占位直接 return）。
            if (r.ok && !r.stubbed) {
                o << "// va=0x" << hexva(fn.first) << " size=" << fn.second
                  << " insns=" << r.insnCount << "\n";
                o << r.code << "\n";
                ++st.ok;
            } else if (r.ok && r.stubbed) {
                o << "// va=0x" << hexva(fn.first) << " size=" << fn.second
                  << " insns=" << r.insnCount << " STUBBED-FULL (no partial exec)\n";
                std::string mn;
                for (const auto& m : r.stubMnems) { if (!mn.empty()) mn += ","; mn += m; }
                o << "void sub_" << hexva(fn.first) << "(X64Ctx* ctx) {\n"
                     "  UNIMPL_FUNC_M(0x" << hexva(fn.first) << "ULL, \"" << mn << "\");\n}\n\n";
                ++st.stubbed;
            } else {
                o << "// va=0x" << hexva(fn.first) << " LIFT-FAILED:";
                for (const auto& u : r.unsupported) o << " " << u;
                o << "\nvoid sub_" << hexva(fn.first) << "(X64Ctx* ctx) {\n"
                     "  UNIMPL_FUNC(0x" << hexva(fn.first) << "ULL);\n}\n\n";
                ++st.failed;
                std::string reason = r.unsupported.empty() ? "unknown" : r.unsupported[0];
                st.failReasons[reason]++;
            }
        }
    }

    // dispatch_table.cpp
    {
        std::ofstream o(outDir + "/dispatch_table.cpp");
        o << "// 间接调用分发表（55,712 项，二分查找友好）\n#include \"all_decls.h\"\n\n";
        o << "struct DispatchEntry { uint64_t va; RecompFn fn; };\n";
        o << "static const DispatchEntry kDispatch[] = {\n";
        for (const auto& fn : list)
            o << "  {0x" << hexva(fn.first) << "ULL, sub_" << hexva(fn.first) << "},\n";
        o << "};\n\n";
        o << "void init_dispatch_table(const char* extra_url, void* extra) {\n"
             "  (void)extra_url; (void)extra;\n"
             "  for (const auto& e : kDispatch) register_recomp_fn(e.va, e.fn);\n"
             "}\n";
    }

    // 所有 IAT 入口的弱定义占位（手写垫片覆盖它）
    {
        std::ofstream o(outDir + "/shims_auto.cpp");
        o << "// 自动生成的 IAT 占位（weak，手写垫片优先）\n#include \"all_decls.h\"\n\n";
        for (const auto& im : pe.imports) {
            o << "__attribute__((weak)) void shim_" << im.dll << "_" << im.name
              << "(X64Ctx* ctx) {\n  UNIMPL_API(\"" << im.dll << "!" << im.name << "\");\n}\n";
        }
    }

    // 清单
    {
        std::ofstream o(outDir + "/manifest.tsv");
        o << "va\tsize\tshard\n";
        for (int si = 0; si < shards; ++si)
            for (const auto& fn : buckets[(size_t)si])
                o << "0x" << hexva(fn.first) << "\t" << fn.second << "\t" << si << "\n";
    }

    if (!st.failReasons.empty()) {
        std::fprintf(stderr, "[fail] reasons:");
        for (const auto& kv : st.failReasons)
            std::fprintf(stderr, " %s=%zu", kv.first.c_str(), kv.second);
        std::fprintf(stderr, "\n");
    }
    if (stats) *stats = st;
    std::fprintf(stderr, "[shards] total=%zu ok=%zu stubbed=%zu failed=%zu shards=%zu imports=%zu\n",
                 st.total, st.ok, st.stubbed, st.failed, st.shards, pe.imports.size());
}

// ---------------- 数据段函数指针补登 ----------------
size_t expandFunctionListByDataPointers(PeImage& pe) {
    const Section* text = nullptr;
    for (const auto& s2 : pe.sections) if (s2.name == ".text") { text = &s2; break; }
    if (!text) return 0;
    const uint64_t text_lo = pe.image_base + text->va;
    const uint64_t text_hi = text_lo + std::max(text->vsize, text->rawsize);

    // ---- 1) 代码里的直接 call/jmp 目标（冷片段，优先级最高）----
    std::vector<uint64_t> work_code;
    {
        std::unordered_set<uint64_t> seen;
        ZydisDecoder dec;
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        for (const auto& fn : pe.functions) {
            const Section* sec = pe.byRva((uint32_t)(fn.first - pe.image_base));
            if (!sec) continue;
            uint32_t base_off = sec->raw + (uint32_t)(fn.first - pe.image_base - sec->va);
            size_t off = 0;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            while (off < fn.second) {
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, pe.data.data() + base_off + off,
                                                         fn.second - off, &insn, ops))) break;
                uint64_t next_rip = fn.first + off + insn.length;
                if ((insn.mnemonic == ZYDIS_MNEMONIC_CALL || insn.mnemonic == ZYDIS_MNEMONIC_JMP) &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                    if (t >= text_lo && t < text_hi && !pe.hasFunction(t) && seen.insert(t).second)
                        work_code.push_back(t);
                }
                off += insn.length;
            }
        }
    }

    // ---- 2) 数据段里的 8 字节函数指针 ----
    std::vector<uint64_t> work_data;
    {
        std::unordered_set<uint64_t> seen;
        for (const auto& sec : pe.sections) {
            if (sec.name == ".text" || sec.exec) continue;
            if (sec.rawsize < 8) continue;
            const uint8_t* p = pe.data.data() + sec.raw;
            for (uint32_t off = 0; off + 8 <= sec.rawsize; off += 8) {
                uint64_t v = 0;
                std::memcpy(&v, p + off, 8);
                if (v >= text_lo && v < text_hi && !pe.hasFunction(v) && seen.insert(v).second)
                    work_data.push_back(v);
            }
        }
    }

    size_t added = 0;
    std::unordered_map<std::string, size_t> why;
    std::unordered_set<uint64_t> visited;

    auto process = [&](std::vector<uint64_t>& work, size_t cap) {
        size_t local = 0;
        while (!work.empty() && local < cap) {
            uint64_t v = work.back();
            work.pop_back();
            if (!visited.insert(v).second) continue;
            if (pe.hasFunction(v)) continue;
            if (pe.functions.size() > 140000) return;
            // 与 addExtraEntries 同理：函数体内部的地址不能当独立入口。
            {
                auto it2 = std::upper_bound(pe.functions.begin(), pe.functions.end(), v,
                                            [](uint64_t val, const std::pair<uint64_t, uint32_t>& f) {
                                                return val < f.first;
                                            });
                if (it2 != pe.functions.begin()) {
                    --it2;
                    if (v >= it2->first && v < (it2->first + (uint64_t)it2->second)) continue;
                }
            }

            uint64_t base = 0; uint32_t fsize = 0;
            for (const auto& f : pe.functions)
                if (f.first <= v && f.first >= base) { base = f.first; fsize = f.second; }
            uint32_t len = 0;
            if (base && base + fsize > v) {
                len = (uint32_t)(base + fsize - v);
            } else {
                for (const auto& f : pe.functions)
                    if (f.first > v) { len = (uint32_t)(f.first - v); break; }
                if (!len) {
                    const Section* sec = pe.byRva((uint32_t)(v - pe.image_base));
                    if (!sec) continue;
                    uint32_t off = (uint32_t)(v - pe.image_base - sec->va);
                    len = (sec->rawsize > off ? std::min<uint32_t>(sec->rawsize - off, 512) : 0);
                }
            }
            if (!len) continue;

            std::unordered_set<uint64_t> discovered;
            g_needed_entries = &discovered;
            LiftResult r = liftFunctionEx(pe, v, len,
                                          LIFT_ALLOW_CALL | LIFT_TAIL_JUMP |
                                          LIFT_STUB_UNKNOWN | LIFT_FRAGMENT);
            g_needed_entries = nullptr;
            if (!r.ok) {
                why[r.unsupported.empty() ? std::string("no-ok") : r.unsupported[0]]++;
            } else {
                pe.functions.emplace_back(v, len);
                ++added;
                ++local;
            }
            for (uint64_t t : discovered)
                if (!visited.count(t) && !pe.hasFunction(t)) work.push_back(t);
        }
    };

    process(work_code, 40000);
    process(work_data, 12000);

    std::sort(pe.functions.begin(), pe.functions.end());
    pe.functions.erase(std::unique(pe.functions.begin(), pe.functions.end()), pe.functions.end());
    if (!why.empty()) {
        std::fprintf(stderr, "[expand] why:");
        for (const auto& kv : why) std::fprintf(stderr, " %s=%zu", kv.first.c_str(), kv.second);
        std::fprintf(stderr, "\n");
    }
    std::fprintf(stderr, "[expand] code_targets=%zu data_ptrs=%zu extra=%zu functions=%zu\n",
                 work_code.size(), work_data.size(), added, pe.functions.size());
    return added;
}

// ---------------- 可达代码发现版（阶段 3 主路径） ----------------
LiftResult liftReachableEx(const PeImage& pe, uint64_t va, uint32_t size, uint32_t flags) {
    LiftResult res;
    const Section* sec0 = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec0) { res.unsupported.push_back("no-section"); return res; }

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    auto decodeAt = [&](uint64_t addr, ZydisDecodedInstruction* insn, ZydisDecodedOperand* ops) -> bool {
        const Section* s2 = pe.byRva((uint32_t)(addr - pe.image_base));
        if (!s2) return false;
        uint32_t off = s2->raw + (uint32_t)(addr - pe.image_base - s2->va);
        if (off >= s2->raw + s2->rawsize) return false;
        size_t avail = (size_t)(s2->raw + s2->rawsize - off);
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, pe.data.data() + off, avail, insn, ops));
    };

    // ---- 发现可达指令 ----
    std::map<uint64_t, uint32_t> blocks;
    std::unordered_set<uint64_t> seen;
    std::vector<uint64_t> work{va};
    while (!work.empty() && blocks.size() < 4000) {
        uint64_t addr = work.back();
        work.pop_back();
        if (seen.count(addr)) continue;
        uint64_t cur = addr;
        while (true) {
            if (seen.count(cur)) break;
            if (cur != va && pe.hasFunction(cur)) break;
            const Section* cur_sec = pe.byRva((uint32_t)(cur - pe.image_base));
            if (!cur_sec || !cur_sec->exec) break;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!decodeAt(cur, &insn, ops)) break;
            seen.insert(cur);
            blocks[cur] = insn.length;
            const char* m = ZydisMnemonicGetString(insn.mnemonic);
            std::string mn = m ? m : "?";
            uint64_t next_rip = cur + insn.length;

            if (mn == "ret") break;
            if (mn == "jmp") {
                if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                    if (!pe.hasFunction(t) || t == va) work.push_back(t);
                    break;
                }
                // 跳转表
                if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[0].mem.index != ZYDIS_REGISTER_NONE) {
                    int64_t disp = ops[0].mem.disp.has_displacement ? (int64_t)ops[0].mem.disp.value : 0;
                    uint64_t tbl = 0;
                    if (ops[0].mem.base == ZYDIS_REGISTER_RIP) tbl = next_rip + disp;
                    else if (ops[0].mem.base == ZYDIS_REGISTER_NONE) tbl = (uint64_t)(uint32_t)disp;
                    int scale = (int)ops[0].mem.scale;
                    if (tbl && (scale == 8 || scale == 4)) {
                        for (int k = 0; k < 256; ++k) {
                            uint64_t raw = 0;
                            if (!readGuestQword(pe, tbl + (uint64_t)k * scale, &raw)) break;
                            if (!raw) continue;
                            work.push_back(raw);
                        }
                    }
                }
                break;
            }
            const bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
            if (isJcc && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                work.push_back(t);
                cur = next_rip;
                continue;
            }
            if (mn == "jrcxz" || mn == "jecxz" || mn == "jcxz") {
                if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                    work.push_back(t);
                }
                cur = next_rip;
                continue;
            }
            cur = next_rip;
        }
    }
    if (blocks.empty()) { res.unsupported.push_back("no-code"); return res; }

    std::unordered_set<uint64_t> labelSet;
    for (const auto& kv : blocks) labelSet.insert(kv.first);
    const uint64_t max_end = blocks.rbegin()->first + blocks.rbegin()->second;
    const uint64_t effSize = max_end > va ? (max_end - va) : size;

    Emit e;
    e.flags = flags;
    std::string lastMn;
    e.out << "void sub_" << std::hex << va << std::dec << "(X64Ctx* ctx) {\n"
          << "  MEW_SET_CUR_FN(ctx, 0x" << hexStr(va) << "ULL);\n";

    for (const auto& kv : blocks) {
        const uint64_t rip = kv.first;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!decodeAt(rip, &insn, ops)) { e.unsupported.push_back("decode-fail"); break; }
        const uint64_t next_rip = rip + insn.length;
        const char* m = ZydisMnemonicGetString(insn.mnemonic);
        std::string mn = m ? m : "?";
        e.count++;

        for (uint16_t oi = 0; oi < insn.operand_count; ++oi) {
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.usesMemory = true;
                if (oi == 0) e.writesMemory = true;
            }
        }
        if (e.count == 1) {
            if (mn == "push" ||
                (mn == "sub" && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RSP) ||
                (mn == "mov" && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY)) {
                e.hasPrologue = true;
            }
        }

        e.out << "L_" << std::hex << rip << std::dec << ": ;\n";

        bool xmmOp = false;
        for (uint16_t oi = 0; oi < insn.operand_count; ++oi)
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_REGISTER && xmmId(ops[oi].reg.value) >= 0) xmmOp = true;

        const bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
        const std::string setcc = ccSuffix(mn, "set");
        const std::string cmovcc = ccSuffix(mn, "cmov");

        if (tryEmitSse(e, pe, mn, insn, ops, next_rip)) {
            /* SSE 已处理 */
        } else if (mn == "nop" || mn == "int3" || mn == "endbr64" || mn == "pause") {
            /* no-op */
        } else if (mn == "ret") {
            e.out << "  MEW_RET_TRACE(ctx);\n  ctx->rsp += 8; return;\n";
        } else if (mn == "leave") {
            e.out << "  write_reg(ctx,4,read_reg(ctx,5,8),8); write_reg(ctx,5,mem_read<uint64_t>(ctx,ctx->rsp),8); ctx->rsp += 8;\n";
        } else if (mn == "push") {
            e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, "
                  << valExpr(pe, insn, ops[0], next_rip, e) << ");\n";
        } else if (mn == "pop") {
            storeExpr(pe, insn, ops[0], "mem_read<uint64_t>(ctx,ctx->rsp)", next_rip, 8, e);
            e.out << "  ctx->rsp += 8;\n";
        } else if (mn == "mov" || mn == "movzx" || mn == "movsx" || mn == "movsxd" || mn == "movd" || mn == "movq") {
            std::string v = valExpr(pe, insn, ops[1], next_rip, e);
            if (mn == "movzx") {
                unsigned bits = ops[1].size;
                if (bits < 64) {
                    std::ostringstream t;
                    t << std::hex << ((1ULL << bits) - 1);
                    v = "(" + v + " & 0x" + t.str() + "ULL)";
                }
            } else if (mn == "movsx" || mn == "movsxd") {
                v = "(uint64_t)(int64_t)(int" + std::to_string(ops[1].size) + "_t)(" + v + ")";
            }
            storeExpr(pe, insn, ops[0], v, next_rip, ops[0].size / 8, e);
        } else if (mn == "lea") {
            storeExpr(pe, insn, ops[0], addrExpr(pe, ops[1], next_rip, e), next_rip, ops[0].size / 8, e);
        } else if (mn == "add" || mn == "sub" || mn == "cmp" || mn == "and" || mn == "or" ||
                   mn == "xor" || mn == "test") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = valExpr(pe, insn, ops[1], next_rip, e);
            int w = ops[0].size / 8;
            std::string call;
            if (mn == "add") call = "add_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            else if (mn == "sub" || mn == "cmp") call = "sub_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            else {
                std::string opx = (mn == "and" || mn == "test") ? "&" : (mn == "or") ? "|" : "^";
                call = "logic_flags(ctx,(" + a + " " + opx + " " + b + ")," + std::to_string(w) + ")";
            }
            if (mn == "cmp" || mn == "test") e.out << "  (void)" << call << ";\n";
            else storeExpr(pe, insn, ops[0], call, next_rip, w, e);
        } else if (mn == "inc" || mn == "dec") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            int w = ops[0].size / 8;
            std::string call = (mn == "inc") ? "add_flags(ctx," + a + ",1ULL," + std::to_string(w) + ")"
                                             : "sub_flags(ctx," + a + ",1ULL," + std::to_string(w) + ")";
            storeExpr(pe, insn, ops[0], call, next_rip, w, e);
        } else if (mn == "neg") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            int w = ops[0].size / 8;
            storeExpr(pe, insn, ops[0], "sub_flags(ctx,0ULL," + a + "," + std::to_string(w) + ")", next_rip, w, e);
        } else if (mn == "not") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            storeExpr(pe, insn, ops[0], "(~" + a + ")", next_rip, ops[0].size / 8, e);
        } else if (mn == "cdqe" || mn == "cwde" || mn == "cbw" || mn == "cdq" || mn == "cqo" || mn == "cwd") {
            if (mn == "cdqe") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int32_t)read_reg(ctx,0,4),8);\n";
            else if (mn == "cwde") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int16_t)read_reg(ctx,0,2),4);\n";
            else if (mn == "cbw") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int8_t)read_reg(ctx,0,1),2);\n";
            else if (mn == "cdq") e.out << "  write_reg(ctx,2,(uint64_t)(int64_t)((int64_t)(int32_t)read_reg(ctx,0,4) >> 31),4);\n";
            else e.out << "  write_reg(ctx,2,(uint64_t)((int64_t)read_reg(ctx,0,8) >> 63),8);\n";
        } else if (mn == "imul") {
            // 注意：不能只信 insn.operand_count。实测 49 0F AF D8（imul rbx,r8 两操作数）
            // 会被报成 3 个操作数，第 3 个是 UNUSED —— 旧代码走进 3 操作数分支后
            // 把它当成"立即数 0"，生成 rbx = r8 * 0，_calloc_base 于是申请 1 字节
            // （PTD 要 0x3C8），后续堆块全部重叠、CRT 初始化器 abort。
            // Zydis 会把隐式写出的 RFLAGS 也放进操作数数组（REGISTER 类型但既不是
            // GPR 也不是 XMM），它的 gprId/xmmId 都是 -1、valExpr 退化成 "0"。
            // 所以这里只接受"真实可读写"的操作数。
            const auto imulOpUsable = [](const ZydisDecodedOperand& o) {
                if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) return true;
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) return true;
                if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) return gprId(o.reg.value) >= 0 || xmmId(o.reg.value) >= 0;
                return false;
            };
            int opn = (int)insn.operand_count;
            while (opn > 1 && !imulOpUsable(ops[opn - 1])) --opn;
            if (opn <= 1) {
                e.out << "  { int64_t x=(int64_t)read_reg(ctx,0,8), y=(int64_t)"
                      << valExpr(pe, insn, ops[0], next_rip, e) << "; __int128 p=(__int128)x*y;"
                         " write_reg(ctx,0,(uint64_t)p,8); write_reg(ctx,2,(uint64_t)(p>>64),8); }\n";
            } else if (opn == 2) {
                int id = gprId(ops[0].reg.value);
                int w = ops[0].size / 8;
                e.out << "  write_reg(ctx," << id << ",(uint64_t)((int64_t)read_reg(ctx," << id << "," << w
                      << ") * (int64_t)" << valExpr(pe, insn, ops[1], next_rip, e) << ")," << w << ");\n";
            } else {
                int id = gprId(ops[0].reg.value);
                int w = ops[0].size / 8;
                e.out << "  write_reg(ctx," << id << ",(uint64_t)((int64_t)"
                      << valExpr(pe, insn, ops[1], next_rip, e) << " * (int64_t)"
                      << valExpr(pe, insn, ops[2], next_rip, e) << ")," << w << ");\n";
            }
        } else if (mn == "shl" || mn == "shr" || mn == "sar") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = (insn.operand_count > 1) ? valExpr(pe, insn, ops[1], next_rip, e) : "1ULL";
            int w = ops[0].size / 8;
            std::string shift = (mn == "shl") ? "<<" : ">>";
            if (mn == "sar") {
                storeExpr(pe, insn, ops[0],
                          "(uint64_t)((int64_t)(" + a + ") >> (" + b + " & 63))", next_rip, w, e);
            } else {
                storeExpr(pe, insn, ops[0], "((" + a + ") " + shift + " (" + b + " & 63))", next_rip, w, e);
            }
        } else if (mn == "rol" || mn == "ror") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = (insn.operand_count > 1) ? valExpr(pe, insn, ops[1], next_rip, e) : "1ULL";
            int w = ops[0].size / 8;
            int bits = w * 8;
            std::string fn = (mn == "rol") ? "rotl" : "rotr";
            storeExpr(pe, insn, ops[0], std::string(fn) + "<uint64_t>(" + a + "," + b + ") & " +
                                     std::to_string(bits == 64 ? ~0ULL : ((1ULL << bits) - 1)) + "ULL",
                      next_rip, w, e);
        } else if (mn == "int") {
            uint64_t imm = (insn.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                         ? (uint64_t)ops[0].imm.value.u : 3;
            if (imm == 3) {
                /* int3：断点填充，按 nop 处理 */
            } else {
                /* int 0x29 = __fastfail（CRT 致命路径），int 0x2c = 断言。
                   旧实现当占位跳过，掩盖了真正的失败原因；现在显式报告。 */
                e.out << "  MEW_FASTFAIL(ctx, 0x" << hexStr(rip) << "ULL, " << imm << ");\n";
            }
        } else if (mn == "bt" || mn == "btc" || mn == "btr" || mn == "bts") {
            int w = ops[0].size / 8;
            int nbits = w * 8;
            e.out << "  { uint64_t b=" << valExpr(pe, insn, ops[0], next_rip, e)
                  << "; uint64_t ii=(" << valExpr(pe, insn, ops[1], next_rip, e) << ") & " << (nbits - 1) << ";\n"
                     "    ctx->cf = ((b >> ii) & 1ULL) != 0;\n";
            if (mn == "bts") e.out << "    b |= (1ULL << ii);\n";
            else if (mn == "btr") e.out << "    b &= ~(1ULL << ii);\n";
            else if (mn == "btc") e.out << "    b ^= (1ULL << ii);\n";
            if (mn != "bt") storeExpr(pe, insn, ops[0], "b", next_rip, w, e);
            e.out << "  }\n";
        } else if (mn == "bsf" || mn == "bsr" || mn == "tzcnt" || mn == "lzcnt" || mn == "popcnt") {
            int w = ops[0].size / 8;
            std::string src = valExpr(pe, insn, ops[1], next_rip, e);
            // 注意 bsr 与 lzcnt 的语义相反：
            //   bsr  -> 最高置位 bit 的下标（63 - clz）
            //   lzcnt-> 前导零个数（clz）
            // 以前把两者合成 x64_clz，直接让 _Hash 的桶上限从 2^59 变成 2^4。
            std::string fn = (mn == "bsf" || mn == "tzcnt") ? "x64_ctz"
                           : (mn == "bsr") ? "x64_bsr"
                           : (mn == "lzcnt") ? "x64_clz" : "x64_popcnt";
            storeExpr(pe, insn, ops[0], fn + "(" + src + ", " + std::to_string(w * 8) + ")", next_rip, w, e);
            if (mn == "bsf" || mn == "bsr") {
                e.out << "  (void)sub_flags(ctx," << src << ",0ULL," << w << ");\n";
            }
        } else if (mn == "cmpxchg") {
            int w = ops[0].size / 8;
            std::string dst = valExpr(pe, insn, ops[0], next_rip, e);
            std::string srcv = valExpr(pe, insn, ops[1], next_rip, e);
            uint64_t mask = w >= 8 ? ~0ULL : ((1ULL << (w * 8)) - 1);
            e.out << "  { uint64_t d=" << dst << ", s=" << srcv
                  << ", acc=read_reg(ctx,0," << w << ") & " << mask << "ULL;\n"
                     "    (void)sub_flags(ctx,acc,d," << w << ");\n"
                     "    if (ctx->zf) { d = s; } else { write_reg(ctx,0,d," << w << "); }\n";
            storeExpr(pe, insn, ops[0], "d", next_rip, w, e);
            e.out << "  }\n";
        } else if (mn == "xadd") {
            int w = ops[0].size / 8;
            std::string dst = valExpr(pe, insn, ops[0], next_rip, e);
            std::string srcv = valExpr(pe, insn, ops[1], next_rip, e);
            e.out << "  { uint64_t d=" << dst << ", s=" << srcv << ";\n";
            storeExpr(pe, insn, ops[1], "d", next_rip, w, e);
            e.out << "    uint64_t r=add_flags(ctx,d,s," << w << ");\n";
            storeExpr(pe, insn, ops[0], "r", next_rip, w, e);
            e.out << "  }\n";
        } else if (!xmmOp && (mn == "stosb" || mn == "stosw" || mn == "stosd" || mn == "stosq" ||
                   mn == "movsb" || mn == "movsw" || mn == "movsd" || mn == "movsq" ||
                   mn == "lodsb" || mn == "lodsw" || mn == "lodsd" || mn == "lodsq" ||
                   mn == "scasb" || mn == "scasw" || mn == "scasd" || mn == "scasq" ||
                   mn == "cmpsb" || mn == "cmpsw" || mn == "cmpsd" || mn == "cmpsq")) {
            const char* base = mn.c_str();
            char op = base[0];
            char sz = mn.back();
            int bytes = (sz == 'b') ? 1 : (sz == 'w') ? 2 : (sz == 'd') ? 4 : 8;
            int rep = (insn.attributes & ZYDIS_ATTRIB_HAS_REP) ? 1 : 0;
            int repne = (insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) ? 1 : 0;
            if (op == 's' && mn.rfind("stos", 0) == 0) e.out << "  x64_stos(ctx," << bytes << "," << rep << ");\n";
            else if (op == 'm') e.out << "  x64_movs(ctx," << bytes << "," << rep << ");\n";
            else if (op == 'l') e.out << "  x64_lods(ctx," << bytes << "," << rep << ");\n";
            else if (mn.rfind("scas", 0) == 0) e.out << "  x64_scas(ctx," << bytes << "," << rep << "," << repne << ");\n";
            else e.out << "  x64_cmps(ctx," << bytes << "," << rep << "," << repne << ");\n";
        } else if (mn == "cld") {
            e.out << "  ctx->df = false;\n";
        } else if (mn == "std") {
            e.out << "  ctx->df = true;\n";
        } else if (mn == "clc") {
            e.out << "  ctx->cf = false;\n";
        } else if (mn == "stc") {
            e.out << "  ctx->cf = true;\n";
        } else if (mn == "cmc") {
            e.out << "  ctx->cf = !ctx->cf;\n";
        } else if (mn == "xchg") {
            std::string v0 = valExpr(pe, insn, ops[0], next_rip, e);
            std::string v1 = valExpr(pe, insn, ops[1], next_rip, e);
            e.out << "  { uint64_t t0=" << v0 << "; uint64_t t1=" << v1 << ";\n";
            storeExpr(pe, insn, ops[0], "t1", next_rip, ops[0].size / 8, e);
            storeExpr(pe, insn, ops[1], "t0", next_rip, ops[1].size / 8, e);
            e.out << "  }\n";
        } else if (mn == "cpuid") {
            e.out << "  { uint32_t a=(uint32_t)read_reg(ctx,0,4), b=0, c=(uint32_t)read_reg(ctx,1,4), d=0;\n"
                     "    x64_cpuid(a, c, &a, &b, &c, &d);\n"
                     "    write_reg(ctx,0,a,4); write_reg(ctx,3,b,4); write_reg(ctx,2,c,4); write_reg(ctx,1,d,4); }\n";
        } else if (mn == "xgetbv") {
            e.out << "  { uint32_t a=7, d=0; write_reg(ctx,0,a,4); write_reg(ctx,2,d,4); }\n";
        } else if (mn == "xsetbv") {
            /* 忽略：模拟器不管理 XCR */
        } else if (mn == "rdtsc") {
            e.out << "  { uint64_t t=x64_rdtsc(); write_reg(ctx,0,t,4); write_reg(ctx,2,(t>>32),4); }\n";
        } else if (mn == "bswap") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            e.out << "  write_reg(ctx," << gprId(ops[0].reg.value) << ",bswap64(" << a << "),8);\n";
        } else if (mn == "jmp") {
            if (tryEmitCfg(e, pe, mn, ops[0], next_rip)) {
                /* CFG dispatch 已处理 */
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t >= va && t < va + effSize) {
                    if (labelSet.count(t)) {
                        e.out << "  goto L_" << hexStr(t) << ";\n";
                    } else if (flags & LIFT_FRAGMENT) {
                        if (g_needed_entries) g_needed_entries->insert(t);
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                    } else if (flags & LIFT_STUB_UNKNOWN) {
                        e.stubbed = true;
                        e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-missing\");\n";
                    } else {
                        e.unsupported.push_back("jump-missing");
                        break;
                    }
                } else if (flags & LIFT_FRAGMENT) {
                    if (g_needed_entries) g_needed_entries->insert(t);
                    e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                } else if (flags & LIFT_TAIL_JUMP) {
                    // 尾调用：不压模拟返回地址，直接跳/返回
                    if (pe.hasFunction(t)) {
                        e.out << "  return sub_" << hexStr(t) << "(ctx);\n";
                    } else if (const ImportSlot* im = resolveIatThunk(pe, t)) {
                        e.iatCall = true;
                        // jmp [IAT] 是尾调用：本函数的 ret 由垫片代劳，必须把调用方压入的
                        // 返回地址弹掉。否则每个导入跳板都漏 8 字节，逐层累积后
                        // MSVC stack cookie（xor rsp）校验失败 -> __fastfail(2)。
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8; return;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                    }
                } else { e.unsupported.push_back("jump-out-of-func"); break; }
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ops[0].mem.index != ZYDIS_REGISTER_NONE) {
                // switch 跳转表：jmp qword ptr [index*scale + table]
                int64_t disp = ops[0].mem.disp.has_displacement ? (int64_t)ops[0].mem.disp.value : 0;
                uint64_t tbl = 0;
                if (ops[0].mem.base == ZYDIS_REGISTER_RIP) tbl = next_rip + disp;
                else if (ops[0].mem.base == ZYDIS_REGISTER_NONE) tbl = (uint64_t)(uint32_t)disp;
                int idx_reg = gprId(ops[0].mem.index);
                int scale = (int)ops[0].mem.scale;
                bool expanded = false;
                if (tbl && idx_reg >= 0 && (scale == 8 || scale == 4) && effSize < 0x10000) {
                    std::vector<std::pair<uint64_t, uint64_t>> table;  // (index, target)
                    bool all_in = true;
                    for (int k = 0; k < 256; ++k) {
                        uint64_t raw = 0;
                        if (!readGuestQword(pe, tbl + (uint64_t)k * scale, &raw)) { break; }
                        if (!raw) continue;
                        // 表项可能是原始 VA，也可能已被重定位；两种都接受
                        uint64_t t = raw;
                        if (t > (1ULL << 47)) t = (uint64_t)((int64_t)raw - pe.image_base) + pe.image_base;  // no-op 保护
                        if (t < va || t >= va + effSize) { all_in = false; break; }
                        if (!labelSet.count(t)) { all_in = false; break; }
                        table.push_back({(uint64_t)k, t});
                        if (table.size() >= 128) break;
                    }
                    if (all_in && table.size() >= 2) {
                        e.out << "  { uint64_t ix = read_reg(ctx," << idx_reg << ",8);\n"
                                 "    switch (ix) {\n";
                        for (const auto& kv : table)
                            e.out << "      case " << kv.first << "ULL: goto L_" << hexStr(kv.second) << ";\n";
                        e.out << "      default: UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-table-oor\");\n"
                                 "    }\n"
                                 "  }\n";
                        expanded = true;
                    }
                }
                if (!expanded) {
                    if (flags & LIFT_TAIL_JUMP) {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx); return;\n";
                    } else {
                        e.unsupported.push_back("jmp-indirect");
                    }
                }
            } else if (flags & LIFT_TAIL_JUMP) {
                if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t slot = next_rip + (int64_t)ops[0].mem.disp.value;
                    if (const ImportSlot* im = pe.importBySlot(slot)) {
                        e.iatCall = true;
                        // jmp [IAT] 是尾调用：本函数的 ret 由垫片代劳，必须把调用方压入的
                        // 返回地址弹掉。否则每个导入跳板都漏 8 字节，逐层累积后
                        // MSVC stack cookie（xor rsp）校验失败 -> __fastfail(2)。
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8; return;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(mem_read<uint64_t>(ctx,0x" << hexStr(slot) << "ULL), ctx); return;\n";
                    }
                } else {
                    e.indirectCall = true;
                    e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx); return;\n";
                }
            } else {
                e.unsupported.push_back("jmp-indirect");
            }
        } else if (mn == "jrcxz" || mn == "jecxz" || mn == "jcxz") {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            std::string cond = (mn == "jrcxz") ? "(read_reg(ctx,1,8) == 0)"
                             : (mn == "jecxz") ? "(read_reg(ctx,1,4) == 0)"
                                               : "(read_reg(ctx,1,2) == 0)";
            if (t >= va && t < va + effSize && labelSet.count(t)) {
                e.out << "  if (" << cond << ") goto L_" << hexStr(t) << ";\n";
            } else if (flags & LIFT_STUB_UNKNOWN) {
                e.stubbed = true;
                e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"" << mn << "\");\n";
            } else {
                e.unsupported.push_back(mn);
            }
        } else if (isJcc) {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            std::string cond = ccExpr(mn);
            if (t >= va && t < va + effSize && !labelSet.count(t)) {
                if (flags & LIFT_FRAGMENT) {
                    if (g_needed_entries) g_needed_entries->insert(t);
                    e.out << "  if (" << cond << ") { dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return; }\n";
                } else if (flags & LIFT_STUB_UNKNOWN) {
                    e.stubbed = true;
                    e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-missing\");\n";
                } else {
                    e.unsupported.push_back("jump-missing");
                }
                    continue;
            }
            if (t < va || t >= va + effSize) {
                if ((flags & LIFT_FRAGMENT) && !cond.empty()) {
                    if (g_needed_entries) g_needed_entries->insert(t);
                    e.out << "  if (" << cond << ") { dispatch_indirect(0x" << hexStr(t)
                          << "ULL, ctx); return; }\n";
                    continue;
                }
                if ((flags & LIFT_TAIL_JUMP) && pe.hasFunction(t)) {
                    if (cond.empty()) { e.unsupported.push_back(mn); break; }
                    // 目标在另一块：cond 成立即尾跳进冷片段
                    e.out << "  if (" << cond << ") return sub_" << hexStr(t) << "(ctx);\n";
                    continue;
                }
                e.unsupported.push_back("jump-out-of-func"); break;
            }
            if (cond.empty()) { e.unsupported.push_back(mn); break; }
            e.out << "  if (" << cond << ") goto L_" << std::hex << t << std::dec << ";\n";
        } else if (!setcc.empty()) {
            storeExpr(pe, insn, ops[0], "((uint64_t)(" + setcc + "))", next_rip, 1, e);
        } else if (!cmovcc.empty()) {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = valExpr(pe, insn, ops[1], next_rip, e);
            storeExpr(pe, insn, ops[0], "((" + cmovcc + ") ? " + b + " : " + a + ")", next_rip, ops[0].size / 8, e);
        } else if (mn == "call") {
            e.hasCall = true;
            if (tryEmitCfg(e, pe, mn, ops[0], next_rip)) {
                /* CFG dispatch 已处理 */
            } else if (!(flags & LIFT_ALLOW_CALL)) {
                e.unsupported.push_back("call");
            } else {
                const auto pushRet = [&]() {
                    e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, 0x"
                          << hexStr(next_rip) << "ULL);\n";
                };
                if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                    pushRet();
                    if (pe.hasFunction(t)) {
                        e.directCalls++;
                        // 直接调用也要做 ABI 守卫：只测 dispatch 会漏掉直接调用的 rsp 失衡，
                        // 而 MSVC 的 stack cookie 校验对 rsp 极其敏感（失配即 __fastfail(2)）。
                        e.out << "  { AbiSnapshot _s = abi_snap(ctx); uint64_t _c = cur_fn_va();\n"
                                 "    sub_" << hexStr(t) << "(ctx);\n"
                                 "    if (mew_abi_guard_on() || mew_stack_repair_on())\n"
                                 "      abi_guard_after_call(ctx, _s, 0x" << hexStr(t) << "ULL, _c, 8); }\n";
                    } else if (const ImportSlot* im = resolveIatThunk(pe, t)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx, true);\n";
                    }
                } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t slot = next_rip + (int64_t)ops[0].mem.disp.value;
                    pushRet();
                    if (const ImportSlot* im = pe.importBySlot(slot)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(mem_read<uint64_t>(ctx,0x" << hexStr(slot) << "ULL), ctx, true);\n";
                    }
                } else {
                    pushRet();
                    e.indirectCall = true;
                    e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx, true);\n";
                }
            }
        } else if (flags & LIFT_STUB_UNKNOWN) {
            e.stubbed = true;
            if (g_stub_hist) (*g_stub_hist)[mn]++;
            e.stubMnems.push_back(mn);
            e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"" << mn << "\");\n";
        } else {
            e.unsupported.push_back(mn);
        }

        if (!e.unsupported.empty()) break;
        lastMn = mn;

        // 顺序流：下一地址不在已发现集合里就按间接调用处理
        if (blocks.count(next_rip)) {
            e.out << "  goto L_" << hexStr(next_rip) << ";\n";
        } else {
            e.out << "  dispatch_indirect(0x" << hexStr(next_rip) << "ULL, ctx); return;\n";
        }
    }

    res.lastMnemonic = lastMn;
    if (e.unsupported.empty()) e.out << "}\n";
    res.ok = e.unsupported.empty() && e.count > 0;
    res.code = e.out.str();
    res.unsupported = e.unsupported;
    res.insnCount = e.count;
    res.usesRipData = e.usesRipData;
    res.hasCall = e.hasCall;
    res.usesMemory = e.usesMemory;
    res.writesMemory = e.writesMemory;
    res.hasPrologue = e.hasPrologue;
    res.usesNonStackMem = e.usesNonStackMem;
    res.ptrArgMask = e.ptrArgMask;
    res.badMemBase = e.badMemBase;
    res.directCalls = e.directCalls;
    res.indirectCall = e.indirectCall;
    res.iatCall = e.iatCall;
    res.stubbed = e.stubbed;
    res.stubMnems = e.stubMnems;
    return res;
}

LiftResult liftFunctionEx(const PeImage& pe, uint64_t va, uint32_t size, uint32_t flags) {
    if (flags & LIFT_FRAGMENT) return liftReachableEx(pe, va, size, flags);
    return liftLinearEx(pe, va, size, flags);
}

std::vector<std::pair<uint64_t, uint64_t>> findStringRefs(const PeImage& pe, const char* needle) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    const size_t nlen = std::strlen(needle);
    std::vector<uint64_t> targets;
    for (const auto& sec : pe.sections) {
        if (sec.exec || sec.rawsize < nlen) continue;
        const uint8_t* p = pe.data.data() + sec.raw;
        for (uint32_t off = 0; off + nlen <= sec.rawsize; ++off) {
            if (std::memcmp(p + off, needle, nlen) != 0) continue;
            targets.push_back(pe.image_base + sec.va + off);
        }
    }
    if (targets.empty()) return out;
    for (const auto& t : targets) std::fprintf(stderr, "[str] %s @ 0x%llx\n", needle, (unsigned long long)t);
    std::vector<uint64_t> tset(targets.begin(), targets.end());
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    for (const auto& fn : pe.functions) {
        const Section* sec = pe.byRva((uint32_t)(fn.first - pe.image_base));
        if (!sec || !sec->exec) continue;
        size_t off = 0;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(fn.first - pe.image_base - sec->va);
        while (off < fn.second) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, fn.second - off, &insn, ops))) break;
            uint64_t next_rip = fn.first + off + insn.length;
            for (uint16_t oi = 0; oi < insn.operand_count; ++oi) {
                uint64_t ref = 0;
                if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (ops[oi].mem.base == ZYDIS_REGISTER_RIP)) {
                    ref = next_rip + (int64_t)ops[oi].mem.disp.value;
                } else if (ops[oi].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                           ops[oi].size == 32) {
                    ref = (uint64_t)(uint32_t)ops[oi].imm.value.u;
                }
                if (!ref) continue;
                for (uint64_t tv : tset)
                    if (ref == tv || ref == (tv & 0xFFFFFFFFULL))
                        out.push_back({tv, fn.first});
            }
            off += insn.length;
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<uint64_t> findCallers(const PeImage& pe, uint64_t target_va) {
    std::vector<uint64_t> out;
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    for (const auto& fn : pe.functions) {
        const Section* sec = pe.byRva((uint32_t)(fn.first - pe.image_base));
        if (!sec || !sec->exec) continue;
        const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(fn.first - pe.image_base - sec->va);
        size_t off = 0;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        while (off < fn.second) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, fn.second - off, &insn, ops))) break;
            uint64_t next_rip = fn.first + off + insn.length;
            if ((insn.mnemonic == ZYDIS_MNEMONIC_CALL || insn.mnemonic == ZYDIS_MNEMONIC_JMP) &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t == target_va) out.push_back(fn.first);
            }
            off += insn.length;
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static size_t addExtraEntriesImpl(PeImage& pe, const std::vector<uint64_t>& seeds, bool allow_inside);

size_t addExtraEntries(PeImage& pe, const std::vector<uint64_t>& seeds) {
    return addExtraEntriesImpl(pe, seeds, false);
}
// 运行期 discovered_entries.txt 报出来的目标：允许落在函数体内。
// MSVC 常把两个小叶子函数/片段打包进同一条 .pdata（例如 0x140d6adc0 的前 8 字节是
// `xor eax,eax; ret`，真正目标在 +8），严格过滤会把它们全丢掉。
size_t addExtraEntriesAllowInside(PeImage& pe, const std::vector<uint64_t>& seeds) {
    return addExtraEntriesImpl(pe, seeds, true);
}

static size_t addExtraEntriesImpl(PeImage& pe, const std::vector<uint64_t>& seeds, bool allow_inside) {
    size_t added = 0;
    size_t skipped_inside = 0;
    // 种子可能落在某个已知函数体内部（典型：DIR64 槽指向函数尾巴/共享尾声）。
    // 把这种地址当独立入口会从函数中间进入，跳过 prologue，栈立刻错位——
    // 实测 0x140d676d2 就是 0x140d67690 的 "add rsp,0x20; pop rbx; ret"，
    // 被当成函数执行后 pop 出 0x10 地址、随后 __fastfail(7)。
    // 所以：落在任何 .pdata 区间内的种子一律丢弃（片段由 LIFT_FRAGMENT 在所属函数内处理）。
    auto inside_known = [&](uint64_t v) -> bool {
        if (pe.functions.empty()) return false;
        auto it = std::upper_bound(pe.functions.begin(), pe.functions.end(), v,
                                   [](uint64_t val, const std::pair<uint64_t, uint32_t>& f) {
                                       return val < f.first;
                                   });
        if (it == pe.functions.begin()) return false;
        --it;
        return v >= it->first && v < (it->first + (uint64_t)it->second);
    };
    for (uint64_t v : seeds) {
        if (pe.hasFunction(v)) continue;
        if (!allow_inside && inside_known(v)) { ++skipped_inside; continue; }
        const Section* sec = pe.byRva((uint32_t)(v - pe.image_base));
        if (!sec || !sec->exec) continue;
        uint32_t len = 0;
        for (const auto& f : pe.functions)
            if (f.first > v) { len = (uint32_t)(f.first - v); break; }
        if (!len) {
            uint32_t off = (uint32_t)(v - pe.image_base - sec->va);
            len = sec->rawsize > off ? std::min<uint32_t>(sec->rawsize - off, 256) : 0;
        }
        if (!len) continue;
        LiftResult r = liftFunctionEx(pe, v, len, LIFT_ALLOW_CALL | LIFT_TAIL_JUMP |
                                                LIFT_STUB_UNKNOWN | LIFT_FRAGMENT);
        if (!r.ok) continue;
        pe.functions.emplace_back(v, len);
        ++added;
    }
    std::sort(pe.functions.begin(), pe.functions.end());
    pe.functions.erase(std::unique(pe.functions.begin(), pe.functions.end()), pe.functions.end());
    std::fprintf(stderr, "[seeds] added=%zu skipped_inside_func=%zu total=%zu\n",
                 added, skipped_inside, pe.functions.size());
    return added;
}

void stubHistogram(const PeImage& pe, std::map<std::string, size_t>& out, size_t* stubbedFuncs, size_t* totalFuncs) {
    out.clear();
    std::unordered_map<std::string, size_t> hist;
    size_t stubFns = 0, total = 0;
    g_stub_hist = &hist;
    for (const auto& fn : pe.functions) {
        ++total;
        LiftResult r = liftFunctionEx(pe, fn.first, fn.second,
                                      LIFT_ALLOW_CALL | LIFT_TAIL_JUMP |
                                      LIFT_STUB_UNKNOWN | LIFT_FRAGMENT);
        if (r.stubbed) ++stubFns;
    }
    g_stub_hist = nullptr;
    for (const auto& kv : hist) out[kv.first] = kv.second;
    if (stubbedFuncs) *stubbedFuncs = stubFns;
    if (totalFuncs) *totalFuncs = total;
}
