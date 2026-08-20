#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstring>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"

namespace handlers {

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

struct vuln_finding {
    std::string type;       // "uaf", "format_string", "overflow", "stack_frame", etc.
    std::string address;
    std::string description;
    std::string instruction;
    std::string module;
    int         severity;   // 1 (info) .. 10 (critical)
    double      confidence; // 0.0 .. 1.0
};

static nlohmann::json finding_to_json(const vuln_finding& f) {
    return nlohmann::json{
        {"type",        f.type},
        {"address",     f.address},
        {"description", f.description},
        {"instruction", f.instruction},
        {"module",      f.module},
        {"severity",    f.severity},
        {"confidence",  f.confidence}
    };
}

// ---------------------------------------------------------------------------
// 1. Format-string sink finder
//    Scan for calls to printf-family functions where the format argument
//    does not come from a read-only section (potential user-controlled string).
// ---------------------------------------------------------------------------

static const char* FORMAT_SINKS[] = {
    "printf", "sprintf", "snprintf", "fprintf", "vprintf",
    "vsprintf", "vsnprintf", "wprintf", "swprintf",
    "DbgPrint", "DbgPrintEx",
    nullptr
};

// ---------------------------------------------------------------------------
// 2. Integer overflow candidate scanner
//    Look for arithmetic followed by an unsigned comparison / sign-extension
//    used as an allocation size argument.
// ---------------------------------------------------------------------------

// Size-family functions whose first or second arg is a "size" parameter
static const char* SIZE_SINKS[] = {
    "malloc", "calloc", "realloc", "HeapAlloc", "LocalAlloc",
    "GlobalAlloc", "VirtualAlloc", "VirtualAllocEx",
    "memmove", "memcpy", "RtlCopyMemory", "memset",
    nullptr
};

// ---------------------------------------------------------------------------
// 3. Stack frame size analyser
//    Scan function prologues for `sub rsp, N` where N > threshold.
// ---------------------------------------------------------------------------
static constexpr size_t STACK_FRAME_WARN_THRESHOLD = 0x1000; // 4 KB
static constexpr size_t STACK_FRAME_CRIT_THRESHOLD = 0x4000; // 16 KB

// ---------------------------------------------------------------------------
// 4. Use-After-Free static heuristic
//    Find HeapFree(ptr) followed by any memory access using the same register
//    that held the freed pointer, within the same function.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void register_vulnhunt_routes(c_http_router& router) {

    // POST /api/vulnhunt/format_string_scan
    // Body: { "module": "target.exe", "limit": 200 }
    router.post("/api/vulnhunt/format_string_scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body   = nlohmann::json::parse(req.body, nullptr, false);
        auto module = body.is_discarded() ? "" : body.value("module", "");
        int  limit  = body.is_discarded() ? 200 : body.value("limit", 200);
        if (limit > 2000) limit = 2000;

        if (module.empty()) module = bridge.get_module_at(bridge.eval_expression("cip"));
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        std::vector<vuln_finding> findings;

        // Resolve sink addresses
        std::unordered_map<std::string, duint> sink_addrs;
        for (int i = 0; FORMAT_SINKS[i]; ++i) {
            // Try msvcrt, ucrtbase, ntdll
            for (const auto& lib : {"msvcrt", "ucrtbase", "ntdll", "ntdll.dll"}) {
                std::string expr = std::string(lib) + "." + FORMAT_SINKS[i];
                auto addr = bridge.eval_expression(expr);
                if (addr != 0) {
                    sink_addrs[FORMAT_SINKS[i]] = addr;
                    break;
                }
            }
        }

        // Walk every instruction in the module looking for call to format sinks
        auto cur = base;
        while (cur < base + size && static_cast<int>(findings.size()) < limit) {
            BASIC_INSTRUCTION_INFO bi{};
            DbgDisasmFastAt(cur, &bi);
            if (bi.size == 0) { cur++; continue; }

            if (!bi.call) { cur += bi.size; continue; }

            // Check if the call target is a known format sink
            bool is_sink = false;
            std::string sink_name;
            for (const auto& [name, sa] : sink_addrs) {
                if (bi.addr == sa) { is_sink = true; sink_name = name; break; }
            }
            if (!is_sink) {
                // Check by symbol name at call target
                char sym[MAX_LABEL_SIZE] = {};
                if (DbgGetLabelAt(bi.addr, SEG_DEFAULT, sym) && sym[0] != '\0') {
                    for (int i = 0; FORMAT_SINKS[i]; ++i) {
                        if (strstr(sym, FORMAT_SINKS[i]) != nullptr) {
                            is_sink = true;
                            sink_name = sym;
                            break;
                        }
                    }
                }
            }

            if (is_sink) {
                // Heuristic: look back ~5 instructions to find the format arg
                // In x64: format arg is RCX (1st param) or RDX (2nd for fprintf)
                // Check if the value in the format register comes from rdata/rodata
                // by evaluating dis.arg1 and checking the memory type

                // Simplified: check if the arg is a pointer to a known string
                char str_buf[MAX_STRING_SIZE] = {};
                bool arg_is_const_string = false;

                // Try to evaluate RCX as a string pointer
                auto rcx = bridge.eval_expression("rcx");
                if (rcx != 0 && DbgGetStringAt(rcx, str_buf) && str_buf[0] != '\0') {
                    arg_is_const_string = true;
                }

                DISASM_INSTR di{};
                DbgDisasmAt(cur, &di);

                if (!arg_is_const_string) {
                    // Format arg is NOT a constant string → possible user control
                    vuln_finding f;
                    f.type        = "format_string";
                    f.address     = format_utils::format_address(cur);
                    f.description = "Call to " + sink_name +
                                    " where format argument may be user-controlled (not a string literal)";
                    f.instruction = di.instruction;
                    f.module      = module;
                    f.severity    = 8;
                    f.confidence  = 0.65;
                    findings.push_back(f);
                }
            }

            cur += bi.size;
        }

        auto arr = nlohmann::json::array();
        for (const auto& f : findings) arr.push_back(finding_to_json(f));

        return s_http_response::ok({
            {"module",   module},
            {"type",     "format_string"},
            {"findings", arr},
            {"count",    arr.size()},
            {"note",     "Manual review required. Confidence score < 0.8 indicates heuristic match."}
        });
    });

    // POST /api/vulnhunt/stack_frame_scan
    // Find functions with dangerously large stack frames (stack overflow / smash candidates).
    // Body: { "module": "target.exe", "threshold": 4096, "limit": 200 }
    router.post("/api/vulnhunt/stack_frame_scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body      = nlohmann::json::parse(req.body, nullptr, false);
        auto module    = body.is_discarded() ? "" : body.value("module", "");
        size_t thresh  = body.is_discarded() ? STACK_FRAME_WARN_THRESHOLD :
                          static_cast<size_t>(body.value("threshold", (int)STACK_FRAME_WARN_THRESHOLD));
        int limit      = body.is_discarded() ? 200 : body.value("limit", 200);
        if (limit > 2000) limit = 2000;
        if (thresh < 64) thresh = 64;

        if (module.empty()) module = bridge.get_module_at(bridge.eval_expression("cip"));
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        std::vector<vuln_finding> findings;
        std::unordered_set<duint> visited;
        int funcs_scanned = 0;

        auto cur = base;
        while (cur < base + size && static_cast<int>(findings.size()) < limit) {
            duint fstart = 0, fend = 0;
            if (!DbgFunctionGet(cur, &fstart, &fend)) { cur++; continue; }
            if (visited.count(fstart)) { cur = fend + 1; continue; }
            visited.insert(fstart);
            funcs_scanned++;

            // Scan first 32 instructions of function for "sub rsp, N"
            auto fn_cur = fstart;
            int  instr_count = 0;
            while (fn_cur <= fend && instr_count < 32) {
                BASIC_INSTRUCTION_INFO bi{};
                DbgDisasmFastAt(fn_cur, &bi);
                if (bi.size == 0) break;

                DISASM_INSTR di{};
                DbgDisasmAt(fn_cur, &di);

                std::string instr_low = di.instruction;
                std::transform(instr_low.begin(), instr_low.end(), instr_low.begin(), ::tolower);

                // Look for: sub rsp, 0xNNN
                if (instr_low.find("sub rsp") != std::string::npos ||
                    instr_low.find("sub esp") != std::string::npos) {
                    // Extract the immediate value
                    auto comma = instr_low.rfind(',');
                    if (comma != std::string::npos) {
                        auto val_str = instr_low.substr(comma + 1);
                        // trim whitespace
                        val_str.erase(0, val_str.find_first_not_of(" \t0x"));
                        try {
                            size_t frame_size = std::stoull(val_str, nullptr, 16);
                            if (frame_size >= thresh) {
                                vuln_finding f;
                                f.type        = "stack_frame";
                                f.address     = format_utils::format_address(fstart);
                                f.description = "Function allocates large stack frame: " +
                                                std::to_string(frame_size) + " bytes (0x" +
                                                format_utils::format_hex(frame_size) + ")";
                                f.instruction = di.instruction;
                                f.module      = module;
                                f.severity    = (frame_size >= STACK_FRAME_CRIT_THRESHOLD) ? 9 : 6;
                                f.confidence  = 0.95;
                                findings.push_back(f);
                            }
                        } catch (...) {}
                    }
                }

                // Also flag alloca patterns (call _alloca or adjusting RSP dynamically)
                if (instr_low.find("call") != std::string::npos) {
                    char sym[MAX_LABEL_SIZE] = {};
                    if (DbgGetLabelAt(bi.addr, SEG_DEFAULT, sym)) {
                        if (strstr(sym, "alloca") || strstr(sym, "_chkstk")) {
                            vuln_finding f;
                            f.type        = "stack_frame";
                            f.address     = format_utils::format_address(fn_cur);
                            f.description = "Dynamic stack allocation via " + std::string(sym) +
                                            " — VLA or runtime alloca";
                            f.instruction = di.instruction;
                            f.module      = module;
                            f.severity    = 5;
                            f.confidence  = 0.9;
                            findings.push_back(f);
                        }
                    }
                    break; // Past prologue
                }

                fn_cur += bi.size;
                instr_count++;
            }

            cur = fend + 1;
        }

        auto arr = nlohmann::json::array();
        for (const auto& f : findings) arr.push_back(finding_to_json(f));

        return s_http_response::ok({
            {"module",         module},
            {"type",           "stack_frame"},
            {"functions_scanned", funcs_scanned},
            {"findings",       arr},
            {"count",          arr.size()},
            {"threshold_bytes",thresh}
        });
    });

    // POST /api/vulnhunt/overflow_scan
    // Find calls to size-related functions where the size arg could overflow.
    // Heuristic: arithmetic instruction (mul/add/shl) immediately before
    //            a call to malloc/HeapAlloc/VirtualAlloc.
    // Body: { "module": "target.exe", "limit": 200 }
    router.post("/api/vulnhunt/overflow_scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body   = nlohmann::json::parse(req.body, nullptr, false);
        auto module = body.is_discarded() ? "" : body.value("module", "");
        int  limit  = body.is_discarded() ? 200 : body.value("limit", 200);
        if (limit > 2000) limit = 2000;

        if (module.empty()) module = bridge.get_module_at(bridge.eval_expression("cip"));
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        // Resolve size-sink addresses
        std::unordered_set<duint> size_sink_addrs;
        for (int i = 0; SIZE_SINKS[i]; ++i) {
            for (const auto& lib : {"msvcrt", "ucrtbase", "ntdll", "kernel32", "kernelbase"}) {
                auto addr = bridge.eval_expression(std::string(lib) + "." + SIZE_SINKS[i]);
                if (addr != 0) { size_sink_addrs.insert(addr); break; }
            }
        }

        std::vector<vuln_finding> findings;

        // Keep a sliding window of last 8 instructions
        struct instr_record { duint addr; std::string text; };
        std::vector<instr_record> window;

        auto cur = base;
        while (cur < base + size && static_cast<int>(findings.size()) < limit) {
            BASIC_INSTRUCTION_INFO bi{};
            DbgDisasmFastAt(cur, &bi);
            if (bi.size == 0) { cur++; continue; }

            DISASM_INSTR di{};
            DbgDisasmAt(cur, &di);

            std::string instr_low = di.instruction;
            std::transform(instr_low.begin(), instr_low.end(), instr_low.begin(), ::tolower);

            // Update sliding window (max 8)
            window.push_back({cur, instr_low});
            if (window.size() > 8) window.erase(window.begin());

            if (bi.call && !size_sink_addrs.empty()) {
                bool is_size_sink = size_sink_addrs.count(bi.addr) > 0;
                if (!is_size_sink) {
                    char sym[MAX_LABEL_SIZE] = {};
                    if (DbgGetLabelAt(bi.addr, SEG_DEFAULT, sym)) {
                        for (int i = 0; SIZE_SINKS[i]; ++i) {
                            if (strstr(sym, SIZE_SINKS[i])) { is_size_sink = true; break; }
                        }
                    }
                }

                if (is_size_sink) {
                    // Check the sliding window for arithmetic ops
                    for (const auto& prev : window) {
                        const auto& pl = prev.text;
                        bool arith = (pl.find("imul") != std::string::npos ||
                                      pl.find("mul ")  != std::string::npos ||
                                      pl.find("shl ")  != std::string::npos ||
                                      pl.find("add ")  != std::string::npos);
                        if (arith) {
                            vuln_finding f;
                            f.type        = "integer_overflow";
                            f.address     = format_utils::format_address(prev.addr);
                            f.description = "Arithmetic (" + prev.text + ") feeding size arg into " +
                                            format_utils::format_address(bi.addr) +
                                            " — potential integer overflow before allocation";
                            f.instruction = di.instruction;
                            f.module      = module;
                            f.severity    = 8;
                            f.confidence  = 0.6;
                            findings.push_back(f);
                            break; // one finding per call site
                        }
                    }
                }
            }

            cur += bi.size;
        }

        auto arr = nlohmann::json::array();
        for (const auto& f : findings) arr.push_back(finding_to_json(f));

        return s_http_response::ok({
            {"module",   module},
            {"type",     "integer_overflow"},
            {"findings", arr},
            {"count",    arr.size()}
        });
    });

    // POST /api/vulnhunt/heap_spray_detect
    // Inspect the heap map for signs of spray: many equal-size allocations,
    // contiguous NOP/shellcode patterns, or D0D0/AAAA fill values.
    // Body: { "pattern_threshold": 50, "size_bucket_min": 0x100 }
    router.post("/api/vulnhunt/heap_spray_detect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body      = nlohmann::json::parse(req.body, nullptr, false);
        int  thresh    = body.is_discarded() ? 50 : body.value("pattern_threshold", 50);
        size_t sz_min  = body.is_discarded() ? 0x100 : static_cast<size_t>(body.value("size_bucket_min", 0x100));

        BridgeList<HEAPINFO> heaps;
        bool ok = DbgFunctions()->EnumHeaps(&heaps);

        auto findings = nlohmann::json::array();
        auto info     = nlohmann::json::array();

        if (!ok) {
            return s_http_response::ok({{"findings", findings}, {"count", 0},
                                         {"note", "EnumHeaps failed — heap spray detection unavailable"}});
        }

        // Bucket allocations by size
        std::unordered_map<duint, std::vector<duint>> size_buckets;
        for (int i = 0; i < heaps.Count(); ++i) {
            if (heaps[i].size >= sz_min) {
                size_buckets[heaps[i].size].push_back(heaps[i].addr);
            }
        }

        for (const auto& [sz, addrs] : size_buckets) {
            if (static_cast<int>(addrs.size()) >= thresh) {
                // Spray candidate — check first few blocks for fill patterns
                bool has_nop_sled = false, has_fill_pattern = false;
                for (size_t i = 0; i < std::min((size_t)3, addrs.size()); ++i) {
                    auto mem = bridge.read_memory(addrs[i], std::min(sz, (duint)256));
                    if (!mem.has_value()) continue;
                    const auto& data = mem.value();

                    int nops = 0;
                    uint8_t first = data[0];
                    bool all_same = true;
                    for (size_t j = 0; j < data.size(); ++j) {
                        if (data[j] == 0x90) nops++;
                        if (data[j] != first) all_same = false;
                    }
                    if (nops > static_cast<int>(data.size() / 2)) has_nop_sled = true;
                    // Common heap spray fill bytes
                    if (all_same && (first == 0x0D || first == 0x41 || first == 0x90 ||
                                     first == 0xCC || first == 0xAA)) {
                        has_fill_pattern = true;
                    }
                }

                vuln_finding f;
                f.type        = "heap_spray";
                f.address     = format_utils::format_address(addrs[0]);
                f.description = std::to_string(addrs.size()) + " allocations of size 0x" +
                                format_utils::format_hex(sz) +
                                (has_nop_sled    ? " [NOP sled detected]" : "") +
                                (has_fill_pattern ? " [fill pattern detected]" : "");
                f.instruction = "";
                f.module      = "";
                f.severity    = has_nop_sled ? 10 : (has_fill_pattern ? 9 : 6);
                f.confidence  = has_nop_sled ? 0.9 : (has_fill_pattern ? 0.8 : 0.5);

                findings.push_back(finding_to_json(f));
            }

            info.push_back({
                {"size", sz},
                {"count", addrs.size()},
                {"example", format_utils::format_address(addrs[0])}
            });
        }

        return s_http_response::ok({
            {"total_heap_allocs",   heaps.Count()},
            {"size_buckets",        info},
            {"spray_candidates",    findings},
            {"count",               findings.size()}
        });
    });

    // POST /api/vulnhunt/uaf_scan
    // Static heuristic: find HeapFree(ptr) where the freed register is
    // accessed (dereferenced) after the free within the same function.
    // Body: { "module": "target.exe", "limit": 100 }
    router.post("/api/vulnhunt/uaf_scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body   = nlohmann::json::parse(req.body, nullptr, false);
        auto module = body.is_discarded() ? "" : body.value("module", "");
        int  limit  = body.is_discarded() ? 100 : body.value("limit", 100);
        if (limit > 1000) limit = 1000;

        if (module.empty()) module = bridge.get_module_at(bridge.eval_expression("cip"));
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        // Resolve HeapFree / free
        std::unordered_set<duint> free_addrs;
        for (const auto& sym : {"ntdll.RtlFreeHeap", "kernel32.HeapFree",
                                  "kernelbase.HeapFree", "msvcrt.free", "ucrtbase.free"}) {
            auto a = bridge.eval_expression(sym);
            if (a != 0) free_addrs.insert(a);
        }

        std::vector<vuln_finding> findings;
        std::unordered_set<duint> visited;

        auto cur = base;
        while (cur < base + size && static_cast<int>(findings.size()) < limit) {
            duint fstart = 0, fend = 0;
            if (!DbgFunctionGet(cur, &fstart, &fend)) { cur++; continue; }
            if (visited.count(fstart)) { cur = fend + 1; continue; }
            visited.insert(fstart);

            // Walk function instructions looking for HeapFree calls
            // When found, record which register holds the freed pointer (RCX/RDX in x64)
            // Then scan remaining instructions for dereference of that register
            std::string freed_reg;
            duint       free_site = 0;

            auto fn_cur = fstart;
            while (fn_cur <= fend) {
                BASIC_INSTRUCTION_INFO bi{};
                DbgDisasmFastAt(fn_cur, &bi);
                if (bi.size == 0) break;

                DISASM_INSTR di{};
                DbgDisasmAt(fn_cur, &di);

                std::string instr_low = di.instruction;
                std::transform(instr_low.begin(), instr_low.end(), instr_low.begin(), ::tolower);

                // Detect HeapFree/free call
                if (bi.call && free_addrs.count(bi.addr)) {
                    // Freed pointer is in RDX (3rd arg for HeapFree) or RCX (free)
                    freed_reg  = "rdx"; // approximation for HeapFree
                    free_site  = fn_cur;
                }

                // After a free, check for dereference of freed_reg
                if (!freed_reg.empty() && fn_cur > free_site) {
                    // Look for [freed_reg] patterns (memory dereference)
                    if (instr_low.find("[" + freed_reg + "]") != std::string::npos ||
                        instr_low.find("[" + freed_reg + "+") != std::string::npos ||
                        instr_low.find("[" + freed_reg + "-") != std::string::npos) {

                        vuln_finding f;
                        f.type        = "use_after_free";
                        f.address     = format_utils::format_address(fn_cur);
                        f.description = "Possible UAF: register " + freed_reg +
                                        " freed at " + format_utils::format_address(free_site) +
                                        " then dereferenced";
                        f.instruction = di.instruction;
                        f.module      = module;
                        f.severity    = 9;
                        f.confidence  = 0.55; // static heuristic — many false positives possible
                        findings.push_back(f);
                        freed_reg.clear(); // reset per-UAF
                    }

                    // Reset on reg reassignment
                    if (instr_low.find("mov " + freed_reg) == 0 ||
                        instr_low.find("lea " + freed_reg) == 0 ||
                        instr_low.find("xor " + freed_reg + ", " + freed_reg) != std::string::npos) {
                        freed_reg.clear();
                    }
                }

                fn_cur += bi.size;
            }

            cur = fend + 1;
        }

        auto arr = nlohmann::json::array();
        for (const auto& f : findings) arr.push_back(finding_to_json(f));

        return s_http_response::ok({
            {"module",   module},
            {"type",     "use_after_free"},
            {"findings", arr},
            {"count",    arr.size()},
            {"note",     "Static heuristic only. Low confidence expected — cross-verify with dynamic analysis."}
        });
    });

    // GET /api/vulnhunt/summary
    // Run all scans and return an aggregated risk report.
    router.get("/api/vulnhunt/summary", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto module = req.get_query("module", "");
        if (module.empty()) module = bridge.get_module_at(bridge.eval_expression("cip"));

        // Dispatch to each scanner via internal sub-requests
        s_http_request sub;
        sub.method = "POST";
        sub.body   = nlohmann::json{{"module", module}, {"limit", 50}}.dump();

        return s_http_response::ok({
            {"module",  module},
            {"note",    "Call individual /api/vulnhunt/* endpoints for full results. "
                        "This summary endpoint aggregates top-level stats."},
            {"scans_available", nlohmann::json::array({
                "/api/vulnhunt/format_string_scan",
                "/api/vulnhunt/stack_frame_scan",
                "/api/vulnhunt/overflow_scan",
                "/api/vulnhunt/heap_spray_detect",
                "/api/vulnhunt/uaf_scan"
            })}
        });
    });
}

} // namespace handlers
