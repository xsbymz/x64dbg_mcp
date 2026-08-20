#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstring>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::vector<std::pair<std::string, std::string>> get_module_list() {
    std::vector<std::pair<std::string, std::string>> modules;
    MEMMAP memmap{};
    if (!DbgMemMap(&memmap)) return modules;

    for (int i = 0; i < memmap.count; ++i) {
        const auto& page = memmap.page[i];
        if (page.mbi.State != MEM_COMMIT) continue;
        std::string info = page.info;
        if (info.empty()) continue;
        std::string lower = info;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (lower.size() > 4 && (lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".sys"))) {
            auto last_sep = info.find_last_of("\\/");
            std::string mod_name = (last_sep != std::string::npos) ? info.substr(last_sep + 1) : info;
            bool found = false;
            for (const auto& m : modules) {
                if (m.first == mod_name) { found = true; break; }
            }
            if (!found) {
                modules.emplace_back(mod_name, format_utils::format_address(reinterpret_cast<duint>(page.mbi.BaseAddress)));
            }
        }
    }

    if (memmap.page) BridgeFree(memmap.page);
    return modules;
}

static duint resolve_function(const std::string& module, const std::string& func) {
    std::string expr = module + ":" + func;
    auto addr = DbgValFromString(expr.c_str());
    if (addr == 0) {
        expr = module + "." + func;
        addr = DbgValFromString(expr.c_str());
    }
    return addr;
}

static bool is_likely_canary(duint value) {
    if (value == 0) return false;
    if (value == 0xFFFFFFFFFFFFFFFFULL) return false;
    uint8_t byte_count[256] = {};
    for (int i = 0; i < 8; ++i) {
        byte_count[(value >> (i * 8)) & 0xFF]++;
    }
    int unique_bytes = 0;
    for (int i = 0; i < 256; ++i) {
        if (byte_count[i] > 0) unique_bytes++;
    }
    return unique_bytes >= 3;
}

static duint get_module_base(const std::string& module_name) {
    MEMMAP memmap{};
    if (!DbgMemMap(&memmap)) return 0;

    duint base = 0;
    for (int i = 0; i < memmap.count; ++i) {
        const auto& page = memmap.page[i];
        if (page.mbi.State != MEM_COMMIT) continue;
        std::string info = page.info;
        if (info.empty()) continue;
        auto last_sep = info.find_last_of("\\/");
        std::string mod_name = (last_sep != std::string::npos) ? info.substr(last_sep + 1) : info;
        if (_stricmp(mod_name.c_str(), module_name.c_str()) == 0) {
            base = reinterpret_cast<duint>(page.mbi.BaseAddress);
            break;
        }
    }

    if (memmap.page) BridgeFree(memmap.page);
    return base;
}

void register_corruption_routes(c_http_router& router) {
    // GET /api/corruption/stack_canary?address= - Detect stack canary/stack cookie
    router.get("/api/corruption/stack_canary", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto mem = bridge.read_memory(address, sizeof(duint));
        if (!mem.has_value() || mem->size() < sizeof(duint)) {
            return s_http_response::internal_error("Failed to read memory at " + address_str);
        }

        duint canary_value = 0;
        memcpy(&canary_value, mem->data(), sizeof(duint));

        bool is_initialized = (canary_value != 0 && canary_value != 0xFFFFFFFFFFFFFFFFULL);
        bool canary_found = is_likely_canary(canary_value);

        nlohmann::json result = {
            {"canary_found", canary_found},
            {"canary_value", format_utils::format_address(canary_value)},
            {"canary_address", format_utils::format_address(address)},
            {"is_initialized", is_initialized}
        };

        if (canary_found) {
            result["xor_key"] = format_utils::format_address(canary_value ^ 0x4141414141414141ULL);
            result["note"] = "Value appears to be a stack canary (high entropy, non-zero)";
        } else {
            result["note"] = "Value does not appear to be a valid canary (all zeros, all ones, or low entropy)";
        }

        return s_http_response::ok(result);
    });

    // GET /api/corruption/format_string?address=&count= - Detect potential format string vulnerabilities
    router.get("/api/corruption/format_string", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto count_str = req.get_query("count", "64");

        auto address = bridge.eval_expression(address_str);
        auto count = format_utils::safe_parse_int(count_str, 64);
        if (count < 1) count = 1;
        if (count > 4096) count = 4096;

        auto result = bridge.disassemble_at(address, count);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        const char* format_funcs[] = {
            "printf", "sprintf", "snprintf", "fprintf", "vprintf",
            "vsprintf", "vsnprintf", "vfprintf", "scanf", "sscanf"
        };

        auto vulnerabilities = nlohmann::json::array();

        for (const auto& instr : result.value()) {
            std::string mnemonic = instr.value("mnemonic", "");
            std::string operands = instr.value("operands", "");
            auto instr_addr = format_utils::parse_address(instr["address"].get<std::string>());

            bool is_call = (mnemonic == "call");
            if (!is_call) continue;

            for (const char* func : format_funcs) {
                if (operands.find(func) != std::string::npos) {
                    std::string format_arg = "rcx";
                    if (operands.find("rdx") != std::string::npos) {
                        format_arg = "rdx";
                    }

                    vulnerabilities.push_back({
                        {"address", format_utils::format_address(instr_addr)},
                        {"function", func},
                        {"format_string_argument", format_arg},
                        {"risk_level", "HIGH"},
                        {"description", std::string("Call to ") + func + " with potential user-controlled format string"}
                    });
                    break;
                }
            }
        }

        return s_http_response::ok({
            {"vulnerabilities", vulnerabilities},
            {"scanned_instructions", result->size()}
        });
    });

    // GET /api/corruption/heap_overflow?heap_address= - Detect heap overflow indicators
    router.get("/api/corruption/heap_overflow", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto addr_str = req.get_query("heap_address", "");
        if (addr_str.empty()) {
            return s_http_response::bad_request("Missing 'heap_address' query parameter");
        }

        auto heap_base = format_utils::parse_address(addr_str);
        if (heap_base == 0) {
            return s_http_response::bad_request("Invalid heap address");
        }

        auto issues = nlohmann::json::array();
        bool is_corrupted = false;
        size_t chunk_count = 0;

        auto header = bridge.read_memory(heap_base, 0x200);
        if (!header.has_value() || header->size() < 0x200) {
            issues.push_back({
                {"type", "unreadable"},
                {"address", format_utils::format_address(heap_base)},
                {"description", "Cannot read heap header"}
            });
            is_corrupted = true;
        } else {
            DWORD segment_count = 0;
            memcpy(&segment_count, header->data() + 0x158, sizeof(DWORD));
            if (segment_count > 128) {
                issues.push_back({
                    {"type", "invalid_segment_count"},
                    {"address", format_utils::format_address(heap_base)},
                    {"description", "Segment count exceeds maximum: " + std::to_string(segment_count)}
                });
                is_corrupted = true;
            }

            for (DWORD i = 0; i < segment_count && i < 128; ++i) {
                duint seg_addr = 0;
                size_t seg_ptr_offset = 0x2B0 + i * sizeof(duint);
                if (header->size() >= seg_ptr_offset + sizeof(duint)) {
                    memcpy(&seg_addr, header->data() + seg_ptr_offset, sizeof(duint));
                }
                if (seg_addr == 0) continue;

                auto seg_hdr = bridge.read_memory(seg_addr, 0x80);
                if (!seg_hdr.has_value() || seg_hdr->size() < 0x80) continue;

                duint seg_sig = 0;
                memcpy(&seg_sig, seg_hdr->data() + 0x8, sizeof(duint));
                if (seg_sig != 0xEEFFEEFFEEFFEEFFULL) {
                    issues.push_back({
                        {"type", "invalid_segment_signature"},
                        {"address", format_utils::format_address(seg_addr)},
                        {"description", "Segment signature mismatch: " + format_utils::format_hex(seg_sig)}
                    });
                    is_corrupted = true;
                    break;
                }

                duint first_entry = 0;
                memcpy(&first_entry, seg_hdr->data() + 0x38, sizeof(duint));
                duint last_entry = 0;
                memcpy(&last_entry, seg_hdr->data() + 0x40, sizeof(duint));

                if (first_entry != 0 && first_entry < seg_addr) {
                    issues.push_back({
                        {"type", "invalid_first_entry"},
                        {"address", format_utils::format_address(first_entry)},
                        {"description", "First entry pointer is before segment header"}
                    });
                    is_corrupted = true;
                    break;
                }

                if (first_entry != 0 && last_entry != 0 && first_entry > last_entry) {
                    issues.push_back({
                        {"type", "inverted_chunk_range"},
                        {"address", format_utils::format_address(first_entry)},
                        {"description", "First entry is after last entry"}
                    });
                    is_corrupted = true;
                    break;
                }

                if (first_entry != 0) {
                    duint current = first_entry;
                    size_t local_chunk_count = 0;
                    constexpr size_t MAX_CHUNKS = 200;
#ifdef _WIN64
                    constexpr size_t HEAP_GRANULARITY = 0x10;
#else
                    constexpr size_t HEAP_GRANULARITY = 0x8;
#endif

                    while (current != 0 && current < last_entry + 0x1000 && local_chunk_count < MAX_CHUNKS) {
                        auto entry_hdr = bridge.read_memory(current, 0x10);
                        if (!entry_hdr.has_value() || entry_hdr->size() < 0x10) break;

                        uint16_t chunk_size = 0;
                        memcpy(&chunk_size, entry_hdr->data(), sizeof(uint16_t));

                        if (chunk_size < HEAP_GRANULARITY || chunk_size > 0xFFFF) {
                            issues.push_back({
                                {"type", "invalid_chunk_size"},
                                {"address", format_utils::format_address(current)},
                                {"description", "Chunk size out of range: " + std::to_string(chunk_size)}
                            });
                            is_corrupted = true;
                            break;
                        }

                        chunk_count++;
                        current += static_cast<duint>(chunk_size) * HEAP_GRANULARITY;
                        local_chunk_count++;
                    }
                }
            }
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(heap_base)},
            {"is_corrupted", is_corrupted},
            {"issues", issues},
            {"chunk_count", chunk_count}
        });
    });

    // GET /api/corruption/uaf_candidates?module= - Scan for potential use-after-free patterns
    router.get("/api/corruption/uaf_candidates", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module", "");
        if (module.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto module_base = bridge.get_module_base(module);
        if (module_base == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        MEMMAP memmap{};
        if (!DbgMemMap(&memmap)) {
            return s_http_response::internal_error("Failed to retrieve memory map");
        }

        auto candidates = nlohmann::json::array();
        size_t scanned_pages = 0;

        for (int i = 0; i < memmap.count; ++i) {
            const auto& page = memmap.page[i];
            if (page.mbi.State != MEM_COMMIT) continue;

            duint page_base = reinterpret_cast<duint>(page.mbi.BaseAddress);
            size_t page_size = page.mbi.RegionSize;

            if (page_base >= module_base && page_base < module_base + 0x10000000) {
                scanned_pages++;

                if (page_size > 16 * 1024 * 1024) continue;

                auto mem = bridge.read_memory(page_base, page_size > 65536 ? 65536 : page_size);
                if (!mem.has_value()) continue;

                const auto& bytes = mem.value();
                for (size_t off = 0; off + sizeof(duint) <= bytes.size(); off += sizeof(duint)) {
                    duint ptr_val = 0;
                    memcpy(&ptr_val, bytes.data() + off, sizeof(duint));

                    if (ptr_val >= page_base && ptr_val < page_base + page_size) {
                        if (page.mbi.Protect == PAGE_READWRITE || page.mbi.Protect == PAGE_READWRITE | PAGE_GUARD) {
                            bool is_near_null = (ptr_val < 0x1000);
                            bool points_to_code = (ptr_val >= module_base && ptr_val < module_base + 0x10000000);

                            if (!points_to_code && !is_near_null) {
                                candidates.push_back({
                                    {"address", format_utils::format_address(page_base + static_cast<duint>(off))},
                                    {"chunk_address", format_utils::format_address(ptr_val)},
                                    {"risk_level", "MEDIUM"},
                                    {"description", "Pointer to non-code region within module - potential freed chunk reference"}
                                });
                            }
                        }
                    }
                }
            }
        }

        if (memmap.page) BridgeFree(memmap.page);

        return s_http_response::ok({
            {"module", module},
            {"candidates", candidates},
            {"candidate_count", candidates.size()},
            {"scanned_pages", scanned_pages}
        });
    });
}

} // namespace handlers
