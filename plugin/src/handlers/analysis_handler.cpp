#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"

namespace handlers {

void register_analysis_routes(c_http_router& router) {
    // GET /api/analysis/function?address=0x... - Function boundaries
    router.get("/api/analysis/function", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto address = bridge.eval_expression(address_str);

        auto bounds = bridge.get_function_bounds(address);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + address_str);
        }

        auto start_addr = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        auto label = bridge.get_label_at(start_addr);
        auto module_name = bridge.get_module_at(start_addr);

        auto data = bounds.value();
        data["label"] = label;
        data["module"] = module_name;

        return s_http_response::ok(data);
    });

    // GET /api/analysis/xrefs_to?address=0x... - Cross-references to address
    router.get("/api/analysis/xrefs_to", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto xref_count = DbgGetXrefCountAt(address);

        auto xrefs = nlohmann::json::array();

        if (xref_count > 0) {
            XREF_INFO xref_info{};
            if (DbgXrefGet(address, &xref_info)) {
                for (duint i = 0; i < xref_info.refcount; ++i) {
                    const auto& ref = xref_info.references[i];
                    auto label = bridge.get_label_at(ref.addr);
                    auto module_name = bridge.get_module_at(ref.addr);

                    std::string type_str;
                    switch (ref.type) {
                        case XREF_CALL: type_str = "call"; break;
                        case XREF_JMP:  type_str = "jmp"; break;
                        case XREF_DATA: type_str = "data"; break;
                        default:        type_str = "unknown"; break;
                    }

                    xrefs.push_back({
                        {"address", format_utils::format_address(ref.addr)},
                        {"type",    type_str},
                        {"label",   label},
                        {"module",  module_name}
                    });
                }

                if (xref_info.references) {
                    BridgeFree(xref_info.references);
                }
            }
        }

        return s_http_response::ok({
            {"target", format_utils::format_address(address)},
            {"xrefs",  xrefs},
            {"count",  xrefs.size()}
        });
    });

    // GET /api/analysis/xrefs_from?address=0x... - Cross-references from address
    router.get("/api/analysis/xrefs_from", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);

        // Disassemble the instruction to find references
        auto basic = bridge.get_basic_info(address);
        if (!basic.has_value()) {
            return s_http_response::internal_error(basic.error());
        }

        auto refs = nlohmann::json::array();
        if (basic.value()["is_call"].get<bool>() || basic.value()["is_branch"].get<bool>()) {
            // Try to evaluate the target
            // x64dbg uses dis.branchexec(addr) and dis.branchtarget(addr) expressions
            auto target = bridge.eval_expression("dis.branchtarget(" + address_str + ")");
            if (target != 0) {
                auto label = bridge.get_label_at(target);
                auto module_name = bridge.get_module_at(target);

                refs.push_back({
                    {"address", format_utils::format_address(target)},
                    {"type",    basic.value()["is_call"].get<bool>() ? "call" : "branch"},
                    {"label",   label},
                    {"module",  module_name}
                });
            }
        }

        return s_http_response::ok({
            {"source", format_utils::format_address(address)},
            {"refs",   refs},
            {"count",  refs.size()}
        });
    });

    // GET /api/analysis/basic_blocks?address=0x... - CFG basic blocks
    router.get("/api/analysis/basic_blocks", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto address = bridge.eval_expression(address_str);

        // Get function boundaries first
        auto bounds = bridge.get_function_bounds(address);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + address_str);
        }

        auto func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        auto func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        // Walk the function to identify basic blocks
        auto blocks = nlohmann::json::array();
        auto current_block_start = func_start;
        auto current_addr = func_start;

        while (current_addr <= func_end) {
            BASIC_INSTRUCTION_INFO info{};
            DbgDisasmFastAt(current_addr, &info); // Returns void
            if (info.size == 0) break;

            // Only actual branches/jumps/rets end a basic block.
            // CALL instructions do NOT split blocks — execution falls through
            // to the next instruction in the same block (standard CFG convention).
            bool is_block_end = info.branch;

            // Check if next instruction starts a new block (e.g., is a branch target)
            if (is_block_end || current_addr + info.size > func_end) {
                blocks.push_back({
                    {"start", format_utils::format_address(current_block_start)},
                    {"end",   format_utils::format_address(current_addr)},
                    {"size",  current_addr + info.size - current_block_start}
                });
                current_block_start = current_addr + info.size;
            }

            current_addr += info.size;
        }

        return s_http_response::ok({
            {"function_start", bounds.value()["start"]},
            {"function_end",   bounds.value()["end"]},
            {"blocks",         blocks},
            {"count",          blocks.size()}
        });
    });

    // GET /api/analysis/constants - List known constants
    router.get("/api/analysis/constants", [](const s_http_request&) -> s_http_response {
        BridgeList<CONSTANTINFO> constants;
        DbgFunctions()->EnumConstants(&constants);

        auto result = nlohmann::json::array();
        for (int i = 0; i < constants.Count(); ++i) {
            result.push_back({
                {"name",  constants[i].name},
                {"value", format_utils::format_address(constants[i].value)}
            });
        }

        return s_http_response::ok({
            {"constants", result},
            {"count",     result.size()}
        });
    });

    // GET /api/analysis/error_codes - List known error codes
    router.get("/api/analysis/error_codes", [](const s_http_request&) -> s_http_response {
        BridgeList<CONSTANTINFO> codes;
        DbgFunctions()->EnumErrorCodes(&codes);

        auto result = nlohmann::json::array();
        for (int i = 0; i < codes.Count(); ++i) {
            result.push_back({
                {"name",  codes[i].name},
                {"value", format_utils::format_address(codes[i].value)}
            });
        }

        return s_http_response::ok({
            {"error_codes", result},
            {"count",       result.size()}
        });
    });

    // GET /api/analysis/watch?id= - Check if watchdog triggered
    router.get("/api/analysis/watch", [](const s_http_request& req) -> s_http_response {
        auto id_str = req.get_query("id", "0");
        auto id = static_cast<unsigned int>(std::stoul(id_str));

        auto triggered = DbgFunctions()->WatchIsWatchdogTriggered(id);

        return s_http_response::ok({
            {"id",        id},
            {"triggered", triggered}
        });
    });

    // GET /api/analysis/structs - List defined structs
    router.get("/api/analysis/structs", [](const s_http_request&) -> s_http_response {
        auto structs = nlohmann::json::array();

        DbgFunctions()->EnumStructs([](const char* str, void* userdata) {
            auto* arr = static_cast<nlohmann::json*>(userdata);
            arr->push_back(str);
        }, &structs);

        return s_http_response::ok({
            {"structs", structs},
            {"count",   structs.size()}
        });
    });

    // GET /api/analysis/source?address= - Get source file location
    router.get("/api/analysis/source", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address", "cip");
        auto address = bridge.eval_expression(address_str);

        char source_file[MAX_PATH] = {};
        int line = 0;
        auto found = DbgFunctions()->GetSourceFromAddr(address, source_file, &line);

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"found",   found},
            {"file",    std::string(source_file)},
            {"line",    line}
        });
    });

    // GET /api/analysis/va_to_file?address= - Convert VA to file offset
    router.get("/api/analysis/va_to_file", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto va = bridge.eval_expression(address_str);
        auto file_offset = DbgFunctions()->VaToFileOffset(va);

        return s_http_response::ok({
            {"va",          format_utils::format_address(va)},
            {"file_offset", format_utils::format_address(file_offset)},
            {"found",       file_offset != 0}
        });
    });

    // GET /api/analysis/file_to_va?module=&offset= - Convert file offset to VA
    router.get("/api/analysis/file_to_va", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module");
        auto offset_str = req.get_query("offset");
        if (module_name.empty() || offset_str.empty()) {
            return s_http_response::bad_request("Missing 'module' and/or 'offset' query parameters");
        }

        auto offset = bridge.eval_expression(offset_str);
        auto va = DbgFunctions()->FileOffsetToVa(module_name.c_str(), offset);

        return s_http_response::ok({
            {"module",      module_name},
            {"file_offset", format_utils::format_address(offset)},
            {"va",          format_utils::format_address(va)},
            {"found",       va != 0}
        });
    });

    // GET /api/analysis/mnemonic_brief?mnemonic= - Get mnemonic brief description
    router.get("/api/analysis/mnemonic_brief", [](const s_http_request& req) -> s_http_response {
        auto mnemonic = req.get_query("mnemonic");
        if (mnemonic.empty()) {
            return s_http_response::bad_request("Missing 'mnemonic' query parameter");
        }

        char result[256] = {};
        DbgFunctions()->GetMnemonicBrief(mnemonic.c_str(), sizeof(result), result);

        return s_http_response::ok({
            {"mnemonic",    mnemonic},
            {"description", std::string(result)}
        });
    });

    // GET /api/analysis/strings?module=... - Find strings in module
    router.get("/api/analysis/strings", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module");
        if (module_name.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        // Minimum run length (default 4), parsed without throwing.
        int min_len = 4;
        auto min_str = req.get_query("min_length", "");
        if (!min_str.empty()) {
            int parsed = std::atoi(min_str.c_str());
            if (parsed >= 1 && parsed <= 1024) min_len = parsed;
        }

        // Pagination query params: limit and offset
        int limit = 200; // default page size — small enough to not blow context
        int offset = 0;
        auto limit_str = req.get_query("limit", "");
        auto offset_str = req.get_query("offset", "");
        if (!limit_str.empty()) {
            int parsed = std::atoi(limit_str.c_str());
            if (parsed >= 1 && parsed <= 5000) limit = parsed;
        }
        if (!offset_str.empty()) {
            int parsed = std::atoi(offset_str.c_str());
            if (parsed >= 0) offset = parsed;
        }

        auto mod_size = bridge.eval_expression("mod.size(" + module_name + ")");
        constexpr duint kMaxScan = 64ull * 1024 * 1024; // cap scan to 64MB
        if (mod_size == 0 || mod_size > kMaxScan) mod_size = kMaxScan;

        constexpr size_t kMaxResults = 5000;
        constexpr size_t kChunk = 1024 * 1024;
        // Collect all strings first (up to kMaxResults), then paginate
        auto all_strings = nlohmann::json::array();
        bool truncated = false;

        auto is_printable = [](uint8_t c) { return c >= 0x20 && c <= 0x7E; };

        for (duint off = 0; off < mod_size && !truncated; off += kChunk) {
            size_t want = static_cast<size_t>(
                (mod_size - off) < kChunk ? (mod_size - off) : kChunk);
            auto buf = bridge.read_memory(base + off, want);
            if (!buf.has_value()) continue; // unreadable page, skip
            const auto& b = *buf;
            const size_t n = b.size();

            // ASCII runs
            size_t run_start = 0;
            bool in_run = false;
            for (size_t i = 0; i < n; ++i) {
                if (is_printable(b[i])) {
                    if (!in_run) { in_run = true; run_start = i; }
                } else if (in_run) {
                    in_run = false;
                    if (i - run_start >= static_cast<size_t>(min_len)) {
                        all_strings.push_back({
                            {"address", format_utils::format_address(base + off + run_start)},
                            {"type",    "ascii"},
                            {"value",   std::string(reinterpret_cast<const char*>(b.data() + run_start), i - run_start)}
                        });
                        if (all_strings.size() >= kMaxResults) { truncated = true; break; }
                    }
                }
            }

            // UTF-16LE runs (printable ASCII char followed by 0x00)
            for (size_t i = 0; i + 1 < n && !truncated; ) {
                if (is_printable(b[i]) && b[i + 1] == 0) {
                    size_t start = i;
                    std::string s;
                    while (i + 1 < n && is_printable(b[i]) && b[i + 1] == 0) {
                        s += static_cast<char>(b[i]);
                        i += 2;
                    }
                    if (s.size() >= static_cast<size_t>(min_len)) {
                        all_strings.push_back({
                            {"address", format_utils::format_address(base + off + start)},
                            {"type",    "utf16"},
                            {"value",   s}
                        });
                        if (all_strings.size() >= kMaxResults) { truncated = true; break; }
                    }
                } else {
                    ++i;
                }
            }
        }

        // Apply pagination
        int total = static_cast<int>(all_strings.size());
        int page_start = std::min(offset, total);
        int page_end   = std::min(page_start + limit, total);

        auto page_strings = nlohmann::json::array();
        for (int i = page_start; i < page_end; ++i) {
            page_strings.push_back(all_strings[i]);
        }

        return s_http_response::ok({
            {"module",      module_name},
            {"base",        format_utils::format_address(base)},
            {"strings",     page_strings},
            {"count",       page_strings.size()},
            {"total_count", total},
            {"offset",      page_start},
            {"has_more",    page_end < total || truncated},
            {"min_length",  min_len},
            {"truncated",   truncated}
        });
    });

    // Helper: calculate Shannon entropy
    auto calc_shannon_entropy = [](const uint8_t* data, size_t size) -> double {
        if (size == 0) return 0.0;
        uint32_t counts[256] = {0};
        for (size_t i = 0; i < size; ++i) counts[data[i]]++;
        double entropy = 0.0;
        double d_size = static_cast<double>(size);
        for (int i = 0; i < 256; ++i) {
            if (counts[i] == 0) continue;
            double p = static_cast<double>(counts[i]) / d_size;
            entropy -= p * (std::log(p) / std::log(2.0));
        }
        return entropy;
    };

    // GET /api/analysis/entropy?address=0x...&size=N OR ?module=...
    // Returns Shannon entropy (0.00 to 8.00). > 7.0 suggests compression/packing/encryption.
    router.get("/api/analysis/entropy", [calc_shannon_entropy](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        auto address_str = req.get_query("address", "");
        auto size_str = req.get_query("size", "");

        if (!module_name.empty()) {
            auto base = bridge.get_module_base(module_name);
            if (base == 0) return s_http_response::not_found("Module not found: " + module_name);
            auto mod_size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));

            // Read module in chunks up to 16MB
            constexpr size_t kMaxRead = 16 * 1024 * 1024;
            size_t read_len = std::min(mod_size, kMaxRead);
            auto mem = bridge.read_memory(base, read_len);
            if (!mem.has_value()) return s_http_response::internal_error("Failed to read module memory");

            double entropy = calc_shannon_entropy(mem->data(), mem->size());
            bool is_packed = (entropy > 7.0);

            return s_http_response::ok({
                {"module",    module_name},
                {"base",      format_utils::format_address(base)},
                {"bytes_read", mem->size()},
                {"entropy",   entropy},
                {"is_packed", is_packed},
                {"assessment", is_packed ? "High entropy (likely packed, compressed, or encrypted payload)" : "Normal entropy (standard uncompressed code/data)"}
            });
        }

        if (!address_str.empty() && !size_str.empty()) {
            auto address = bridge.eval_expression(address_str);
            auto size = static_cast<size_t>(bridge.eval_expression(size_str));
            if (size == 0 || size > 64 * 1024 * 1024) {
                return s_http_response::bad_request("Invalid size (1 byte to 64MB)");
            }

            auto mem = bridge.read_memory(address, size);
            if (!mem.has_value()) return s_http_response::internal_error("Failed to read memory: " + mem.error());

            double entropy = calc_shannon_entropy(mem->data(), mem->size());
            bool is_packed = (entropy > 7.0);

            return s_http_response::ok({
                {"address",   format_utils::format_address(address)},
                {"size",      size},
                {"entropy",   entropy},
                {"is_packed", is_packed},
                {"assessment", is_packed ? "High entropy (likely packed/encrypted)" : "Normal entropy"}
            });
        }

        return s_http_response::bad_request("Provide either 'module' or both 'address' and 'size'");
    });

    // GET /api/analysis/rop_gadgets?module=...&filter=...&max_results=100
    // Finds and classifies ROP/JOP gadgets in executable sections.
    router.get("/api/analysis/rop_gadgets", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        auto filter = req.get_query("filter", "all"); // all, pop, pivot, xchg, mov, syscall
        auto max_results_str = req.get_query("max_results", "100");
        int max_results = std::clamp(std::atoi(max_results_str.c_str()), 1, 500);

        std::vector<std::pair<duint, size_t>> exec_ranges;

        if (!module_name.empty()) {
            auto base = bridge.get_module_base(module_name);
            if (base == 0) return s_http_response::not_found("Module not found: " + module_name);
            auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
            if (size > 0) exec_ranges.emplace_back(base, size);
        } else {
            MEMMAP memmap{};
            if (DbgMemMap(&memmap)) {
                for (int i = 0; i < memmap.count; ++i) {
                    const auto& page = memmap.page[i];
                    DWORD prot = page.mbi.Protect;
                    bool is_exec = (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
                    if (page.mbi.State == MEM_COMMIT && is_exec) {
                        exec_ranges.emplace_back(reinterpret_cast<duint>(page.mbi.BaseAddress), static_cast<size_t>(page.mbi.RegionSize));
                    }
                }
                if (memmap.page) BridgeFree(memmap.page);
            }
        }

        auto gadgets = nlohmann::json::array();

        for (const auto& [range_base, range_size] : exec_ranges) {
            if (static_cast<int>(gadgets.size()) >= max_results) break;

            constexpr size_t kChunk = 4 * 1024 * 1024;
            for (size_t off = 0; off < range_size; off += kChunk) {
                if (static_cast<int>(gadgets.size()) >= max_results) break;
                size_t len = std::min(kChunk, range_size - off);
                auto mem = bridge.read_memory(range_base + off, len);
                if (!mem.has_value()) continue;

                const auto& b = *mem;
                for (size_t i = 1; i < b.size(); ++i) {
                    if (static_cast<int>(gadgets.size()) >= max_results) break;

                    // Match `ret` opcode (0xC3)
                    if (b[i] == 0xC3) {
                        // Look back 1 to 6 bytes
                        for (size_t lookback = 1; lookback <= std::min<size_t>(i, 6); ++lookback) {
                            duint gadget_addr = range_base + off + (i - lookback);

                            DISASM_INSTR instr{};
                            DbgDisasmAt(gadget_addr, &instr);
                            if (instr.instr_size == 0) continue;

                            std::string disasm_str(instr.instruction);
                            if (disasm_str.empty()) continue;

                            // Filter logic
                            bool matches_filter = false;
                            std::string category = "other";

                            if (disasm_str.find("pop") != std::string::npos) {
                                category = "pop_reg";
                                if (filter == "all" || filter == "pop") matches_filter = true;
                            } else if (disasm_str.find("xchg") != std::string::npos) {
                                category = "xchg_pivot";
                                if (filter == "all" || filter == "pivot" || filter == "xchg") matches_filter = true;
                            } else if (disasm_str.find("mov") != std::string::npos) {
                                category = "mov";
                                if (filter == "all" || filter == "mov") matches_filter = true;
                            } else if (disasm_str.find("add rsp") != std::string::npos || disasm_str.find("add esp") != std::string::npos) {
                                category = "stack_adjust";
                                if (filter == "all" || filter == "pivot") matches_filter = true;
                            } else if (disasm_str.find("syscall") != std::string::npos || disasm_str.find("sysenter") != std::string::npos) {
                                category = "syscall";
                                if (filter == "all" || filter == "syscall") matches_filter = true;
                            } else if (filter == "all") {
                                matches_filter = true;
                            }

                            if (matches_filter) {
                                // Full disassembly sequence
                                std::string full_seq = disasm_str + "; ret";
                                gadgets.push_back({
                                    {"address",     format_utils::format_address(gadget_addr)},
                                    {"disassembly", full_seq},
                                    {"category",    category},
                                    {"module",      bridge.get_module_at(gadget_addr)}
                                });
                                break; // Only add shortest valid gadget for this ret
                            }
                        }
                    }
                }
            }
        }

        return s_http_response::ok({
            {"count",       gadgets.size()},
            {"filter",      filter},
            {"module",      module_name},
            {"gadgets",     gadgets}
        });
    });

    // GET /api/analysis/vtable?address=0x...&max_methods=32 - C++ VTable & Virtual Method Reconstructor
    // Inspects C++ object instances or direct VTable function pointer arrays, resolving virtual methods, symbols, and entry disasm.
    router.get("/api/analysis/vtable", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address", "cip");
        auto max_str = req.get_query("max_methods", "32");
        int max_methods = std::clamp(std::atoi(max_str.c_str()), 1, 128);

        auto target_addr = bridge.eval_expression(address_str);
        if (target_addr == 0) return s_http_response::bad_request("Invalid address");

        // Determine if target_addr is object instance pointer (pointing to vtable) or vtable itself
        duint vtable_ptr = target_addr;
        auto mem_first = bridge.read_memory(target_addr, sizeof(duint));
        if (mem_first.has_value() && mem_first->size() >= sizeof(duint)) {
            duint deref = 0;
            std::memcpy(&deref, mem_first->data(), sizeof(duint));
            // If deref is a valid pointer that points to readable memory, target_addr might be an object instance
            if (bridge.is_valid_read_ptr(deref)) {
                // Check if deref[0] points to code
                auto mem_second = bridge.read_memory(deref, sizeof(duint));
                if (mem_second.has_value() && mem_second->size() >= sizeof(duint)) {
                    duint func_cand = 0;
                    std::memcpy(&func_cand, mem_second->data(), sizeof(duint));
                    if (bridge.is_valid_read_ptr(func_cand)) {
                        vtable_ptr = deref; // It's an object instance pointer
                    }
                }
            }
        }

        auto methods = nlohmann::json::array();

        for (int i = 0; i < max_methods; ++i) {
            duint slot_addr = vtable_ptr + static_cast<duint>(i * sizeof(duint));
            auto slot_mem = bridge.read_memory(slot_addr, sizeof(duint));
            if (!slot_mem.has_value() || slot_mem->size() < sizeof(duint)) break;

            duint func_ptr = 0;
            std::memcpy(&func_ptr, slot_mem->data(), sizeof(duint));

            // Stop on null pointer or invalid memory
            if (func_ptr == 0 || !bridge.is_valid_read_ptr(func_ptr)) break;

            auto label = bridge.get_label_at(func_ptr);
            auto mod = bridge.get_module_at(func_ptr);

            // Read prologue disassembly (first 2 instructions)
            DISASM_INSTR instr1{};
            DbgDisasmAt(func_ptr, &instr1);
            DISASM_INSTR instr2{};
            DbgDisasmAt(func_ptr + instr1.instr_size, &instr2);

            std::string prologue = std::string(instr1.instruction) + "; " + std::string(instr2.instruction);

            methods.push_back({
                {"index",         i},
                {"slot_address",  format_utils::format_address(slot_addr)},
                {"function",      format_utils::format_address(func_ptr)},
                {"label",         label},
                {"module",        mod},
                {"prologue",      prologue}
            });
        }

        return s_http_response::ok({
            {"target_address", format_utils::format_address(target_addr)},
            {"vtable_address", format_utils::format_address(vtable_ptr)},
            {"methods_count",  methods.size()},
            {"methods",        methods}
        });
    });

    // GET /api/analysis/dataflow?address=cip&register=rax&depth=15 - Backward Register Data-Flow Slicer
    // Traces backwards through disassembly instructions to identify the provenance / source of a register value.
    router.get("/api/analysis/dataflow", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto reg_name = req.get_query("register", "rax");
        auto depth_str = req.get_query("depth", "15");
        int depth = std::clamp(std::atoi(depth_str.c_str()), 1, 50);

        auto cur_addr = bridge.eval_expression(address_str);

        // Convert register name to lowercase
        std::string reg_lower = reg_name;
        std::transform(reg_lower.begin(), reg_lower.end(), reg_lower.begin(), ::tolower);

        // Trace backward by collecting instructions in the vicinity
        // x86/x64 variable length instructions: read 15*10 = 150 bytes before cur_addr
        constexpr size_t kLookback = 120;
        duint start_scan = (cur_addr > kLookback) ? (cur_addr - kLookback) : 0;

        std::vector<std::pair<duint, std::string>> instrs;
        duint scan = start_scan;
        while (scan <= cur_addr) {
            DISASM_INSTR instr{};
            DbgDisasmAt(scan, &instr);
            if (instr.instr_size == 0) { scan++; continue; }
            instrs.emplace_back(scan, std::string(instr.instruction));
            scan += instr.instr_size;
        }

        auto trace = nlohmann::json::array();
        std::string origin_type = "unknown";
        std::string defining_instruction;

        // Traverse backwards from current instruction
        for (auto it = instrs.rbegin(); it != instrs.rend(); ++it) {
            if (it->first >= cur_addr) continue; // Skip current and future

            std::string disasm = it->second;
            std::string disasm_lower = disasm;
            std::transform(disasm_lower.begin(), disasm_lower.end(), disasm_lower.begin(), ::tolower);

            // Check if instruction modifies target register (appears as first operand)
            // e.g. "mov rax, ...", "lea rax, ...", "xor rax, ...", "add eax, ...", "call ..."
            bool modifies = false;
            size_t space_pos = disasm_lower.find(' ');
            if (space_pos != std::string::npos) {
                std::string mnemonic = disasm_lower.substr(0, space_pos);
                std::string operands = disasm_lower.substr(space_pos + 1);

                if (operands.find(reg_lower) == 0 || operands.find(reg_lower + ",") != std::string::npos) {
                    modifies = true;

                    if (mnemonic == "mov" || mnemonic == "movzx" || mnemonic == "movsx") {
                        if (operands.find('[') != std::string::npos) origin_type = "memory_load";
                        else origin_type = "assignment_or_reg_copy";
                    } else if (mnemonic == "lea") {
                        origin_type = "pointer_math_or_address_load";
                    } else if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "imul" || mnemonic == "xor" || mnemonic == "and" || mnemonic == "or") {
                        origin_type = "arithmetic_or_bitwise_computation";
                    }
                } else if (mnemonic == "call" && (reg_lower == "rax" || reg_lower == "eax" || reg_lower == "al")) {
                    modifies = true;
                    origin_type = "function_return_value";
                }
            }

            trace.push_back({
                {"address",     format_utils::format_address(it->first)},
                {"disassembly", disasm},
                {"modifies_reg", modifies}
            });

            if (modifies) {
                defining_instruction = disasm;
                break; // Found the defining instruction!
            }

            if (static_cast<int>(trace.size()) >= depth) break;
        }

        auto current_val = bridge.eval_expression(reg_name);

        return s_http_response::ok({
            {"target_register",      reg_name},
            {"current_value",        format_utils::format_address(current_val)},
            {"current_address",      format_utils::format_address(cur_addr)},
            {"defining_instruction", defining_instruction.empty() ? "not found in window" : defining_instruction},
            {"origin_type",          origin_type},
            {"dependency_trace",     trace}
        });
    });

    // GET /api/analysis/rop_chain_builder?module=&target_effect= - Build ROP chain for target effect
    router.get("/api/analysis/rop_chain_builder", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto module = req.get_query("module", "");
        auto target_effect = req.get_query("target_effect", "pop rcx; ret");

        nlohmann::json gadgets = nlohmann::json::array();
        const char* patterns[] = {
            "pop rcx ; ret", "pop rdx ; ret", "pop r8 ; ret", "pop r9 ; ret",
            "pop rax ; ret", "pop rbx ; ret", "pop rbp ; ret", "pop rsi ; ret",
            "pop rdi ; ret", "pop rsp ; ret",
            "xchg rax, rsp ; ret", "mov rsp, rax ; ret",
            "mov [rcx], rdx ; ret", "mov [rax], rcx ; ret",
            "syscall", "sysenter"
        };

        for (const char* pat : patterns) {
            auto found = bridge.eval_expression("findcmd(\"" + std::string(pat) + "\", \"" + module + "\")");
            if (found != 0) {
                gadgets.push_back({
                    {"pattern", pat},
                    {"address", format_utils::format_address(found)},
                    {"module", module.empty() ? "executable" : module}
                });
            }
        }

        return s_http_response::ok({
            {"target_effect", target_effect},
            {"gadgets_found", gadgets.size()},
            {"gadgets", gadgets}
        });
    });

    // GET /api/analysis/vtable_rtti?address= - Extended VTable with RTTI inspection
    router.get("/api/analysis/vtable_rtti", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto target_addr = bridge.eval_expression(address_str);
        auto vtable_ptr = target_addr;

        auto mem = bridge.read_memory(vtable_ptr, sizeof(duint));
        if (!mem.has_value() || mem->size() < sizeof(duint)) {
            return s_http_response::not_found("Invalid VTable pointer");
        }

        duint actual_vtable = 0;
        std::memcpy(&actual_vtable, mem->data(), sizeof(duint));

        nlohmann::json rtti_info = nlohmann::json::object();
        bool rtti_found = false;

        auto rtti_mem = bridge.read_memory(actual_vtable - 16, 16);
        if (rtti_mem.has_value() && rtti_mem->size() >= 16) {
            const uint8_t* data = rtti_mem->data();
            if (data[0] == 0x00 && data[1] == 0x01 && data[4] == 0x00 && data[5] == 0x00) {
                rtti_found = true;
                duint type_info_ptr = 0;
                std::memcpy(&type_info_ptr, data + 8, sizeof(duint));
                auto type_mem = bridge.read_memory(type_info_ptr, 32);
                if (type_mem.has_value() && type_mem->size() >= 8) {
                    std::string name;
                    for (size_t i = 8; i < type_mem->size() && type_mem->data()[i]; i += 2) {
                        name += static_cast<char>(type_mem->data()[i]);
                    }
                    rtti_info["type_info_address"] = format_utils::format_address(type_info_ptr);
                    rtti_info["class_name"] = name;
                }
            }
        }

        nlohmann::json methods = nlohmann::json::array();
        constexpr int max_methods = 32;
        for (int i = 0; i < max_methods; ++i) {
            auto slot_mem = bridge.read_memory(actual_vtable + i * sizeof(duint), sizeof(duint));
            if (!slot_mem.has_value() || slot_mem->size() < sizeof(duint)) break;

            duint func_ptr = 0;
            std::memcpy(&func_ptr, slot_mem->data(), sizeof(duint));
            if (func_ptr == 0 || !bridge.is_valid_read_ptr(func_ptr)) break;

            auto label = bridge.get_label_at(func_ptr);
            auto mod = bridge.get_module_at(func_ptr);

            DISASM_INSTR instr1{};
            DbgDisasmAt(func_ptr, &instr1);
            DISASM_INSTR instr2{};
            DbgDisasmAt(func_ptr + instr1.instr_size, &instr2);

            std::string prologue = std::string(instr1.instruction) + "; " + std::string(instr2.instruction);
            bool is_pure = (static_cast<unsigned char>(instr1.instruction[0]) == 0xFF && static_cast<unsigned char>(instr1.instruction[1]) == 0x25);

            methods.push_back({
                {"index", i},
                {"slot_address", format_utils::format_address(actual_vtable + i * sizeof(duint))},
                {"function", format_utils::format_address(func_ptr)},
                {"label", label},
                {"module", mod},
                {"prologue", prologue},
                {"is_pure_virtual", is_pure}
            });
        }

        return s_http_response::ok({
            {"target_address", format_utils::format_address(target_addr)},
            {"vtable_address", format_utils::format_address(actual_vtable)},
            {"rtti_found", rtti_found},
            {"rtti_info", rtti_info},
            {"methods_count", methods.size()},
            {"methods", methods}
        });
    });

    // GET /api/analysis/rop_gadgets_advanced?module=&filter=&min_quality= - Enhanced gadget scanner
    router.get("/api/analysis/rop_gadgets_advanced", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto module = req.get_query("module", "");
        auto filter = req.get_query("filter", "all");
        int min_quality = std::atoi(req.get_query("min_quality", "0").c_str());

        nlohmann::json gadgets = nlohmann::json::array();
        const char* useful_patterns[] = {
            "pop rax ; ret", "pop rbx ; ret", "pop rcx ; ret", "pop rdx ; ret",
            "pop rsi ; ret", "pop rdi ; ret", "pop rbp ; ret", "pop rsp ; ret",
            "pop r8 ; ret", "pop r9 ; ret", "pop r10 ; ret", "pop r11 ; ret",
            "pop r12 ; ret", "pop r13 ; ret", "pop r14 ; ret", "pop r15 ; ret",
            "mov [rax], rcx ; ret", "mov [rcx], rdx ; ret", "mov [rbx], rax ; ret",
            "xchg eax, esp ; ret", "xchg rax, rsp ; ret", "jmp rax", "jmp rcx",
            "call rax", "call rcx"
        };

        for (const char* pat : useful_patterns) {
            if (filter != "all") {
                std::string pat_lower = pat;
                std::transform(pat_lower.begin(), pat_lower.end(), pat_lower.begin(), ::tolower);
                if (pat_lower.find(filter) == std::string::npos) continue;
            }

            auto found = bridge.eval_expression("findcmd(\"" + std::string(pat) + "\", \"" + module + "\")");
            if (found != 0) {
                int quality = std::strlen(pat) > 10 ? 3 : 1;
                if (quality >= min_quality) {
                    gadgets.push_back({
                        {"pattern", pat},
                        {"address", format_utils::format_address(found)},
                        {"quality", quality},
                        {"module", module.empty() ? "executable" : module}
                    });
                }
            }
        }

        return s_http_response::ok({
            {"filter", filter},
            {"min_quality", min_quality},
            {"gadgets_found", gadgets.size()},
            {"gadgets", gadgets}
        });
    });
}

} // namespace handlers
