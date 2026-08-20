#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstring>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_module.h"

namespace handlers {

static bool is_base64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static std::string try_xor_decode(const uint8_t* data, size_t size, uint8_t key) {
    std::string result;
    result.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        result += static_cast<char>(data[i] ^ key);
    }
    return result;
}

static bool is_printable_string(const std::string& s, size_t min_len) {
    if (s.size() < min_len) return false;
    size_t printable = 0;
    for (char c : s) {
        if (static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7F) printable++;
        else if (c == '\r' || c == '\n' || c == '\t') printable++;
        else return false;
    }
    return printable >= min_len;
}

void register_config_routes(c_http_router& router) {
    router.post("/api/config/extract", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string module_name = (!body.is_discarded() && body.contains("module")) ? body["module"].get<std::string>() : "";
        size_t min_size = body.value("min_size", 16);
        size_t max_scan_size = body.value("max_scan_size", 10 * 1024 * 1024);
        if (min_size < 4) min_size = 4;
        if (max_scan_size > 100 * 1024 * 1024) max_scan_size = 100 * 1024 * 1024;

        std::vector<std::pair<duint, size_t>> scan_ranges;

        if (!module_name.empty()) {
            auto base = bridge.get_module_base(module_name);
            if (base == 0) {
                return s_http_response::not_found("Module not found: " + module_name);
            }
            auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
            if (size > 0 && static_cast<duint>(size) > max_scan_size) {
                size = max_scan_size;
            }
            scan_ranges.emplace_back(base, size);
        } else {
            MEMMAP memmap{};
            if (DbgMemMap(&memmap)) {
                for (int i = 0; i < memmap.count && static_cast<size_t>(scan_ranges.size()) < 1000; ++i) {
                    const auto& page = memmap.page[i];
                    if (page.mbi.State == MEM_COMMIT &&
                        page.mbi.Protect != PAGE_NOACCESS &&
                        page.mbi.Protect != 0) {
                        size_t region_size = static_cast<size_t>(page.mbi.RegionSize);
                        if (region_size > max_scan_size) region_size = max_scan_size;
                        scan_ranges.emplace_back(reinterpret_cast<duint>(page.mbi.BaseAddress), region_size);
                    }
                }
                if (memmap.page) BridgeFree(memmap.page);
            }
        }

        auto findings = nlohmann::json::array();
        constexpr size_t kChunkSize = 4 * 1024 * 1024;
        const char* xor_prefixes[] = {
            "http://", "https://", "HKEY_", "SOFTWARE\\",
            "cmd.exe", "powershell", "powershell.exe",
            "rundll32", "mshta", "regsvr32"
        };

        for (const auto& [range_base, range_size] : scan_ranges) {
            for (size_t offset = 0; offset < range_size; offset += kChunkSize) {
                if (findings.size() >= 200) break;
                size_t chunk_len = std::min(kChunkSize, range_size - offset);
                auto mem = bridge.read_memory(range_base + offset, chunk_len);
                if (!mem.has_value()) continue;

                const auto& data = mem.value();

                for (size_t i = 0; i < data.size() - 4; ++i) {
                    if (findings.size() >= 200) break;
                    duint cur_addr = range_base + offset + static_cast<duint>(i);

                    if (i + min_size > data.size()) break;

                    size_t remaining = data.size() - i;

                    if (i + 4 <= data.size()) {
                        uint32_t len = 0;
                        memcpy(&len, data.data() + i, sizeof(uint32_t));
                        if (len >= min_size && len < remaining - 4 && len < 0x10000) {
                            if (data[i + 4] == '{') {
                                std::string json_str(reinterpret_cast<const char*>(data.data() + i + 4), len);
                                if (is_printable_string(json_str, min_size)) {
                                    findings.push_back({
                                        {"type", "json_length_prefix"},
                                        {"address", format_utils::format_address(cur_addr)},
                                        {"decoded_value", json_str.substr(0, 256)},
                                        {"confidence", 0.85},
                                        {"encoding_key", ""}
                                    });
                                    i += 4 + static_cast<size_t>(len) - 1;
                                    continue;
                                }
                            }
                        }
                    }

                    size_t base64_len = 0;
                    for (size_t j = i; j < data.size() && is_base64_char(data[j]); ++j) {
                        base64_len++;
                    }
                    if (base64_len >= min_size && base64_len % 4 == 0) {
                        std::string b64(reinterpret_cast<const char*>(data.data() + i), base64_len);
                        findings.push_back({
                            {"type", "base64"},
                            {"address", format_utils::format_address(cur_addr)},
                            {"decoded_value", b64.substr(0, 128)},
                            {"confidence", 0.7},
                            {"encoding_key", ""}
                        });
                        i += base64_len - 1;
                        continue;
                    }

                    for (const char* prefix : xor_prefixes) {
                        size_t plen = strlen(prefix);
                        if (i + plen > data.size()) continue;
                        uint8_t key = data[i] ^ static_cast<uint8_t>(prefix[0]);
                        bool match = true;
                        for (size_t k = 1; k < plen; ++k) {
                            if ((data[i + k] ^ key) != static_cast<uint8_t>(prefix[k])) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            std::string decoded = try_xor_decode(data.data() + i, std::min<size_t>(64, remaining), key);
                            if (is_printable_string(decoded, min_size)) {
                                findings.push_back({
                                    {"type", "xor_string"},
                                    {"address", format_utils::format_address(cur_addr)},
                                    {"decoded_value", decoded.substr(0, 128)},
                                    {"confidence", 0.9},
                                    {"encoding_key", format_utils::format_hex(key)}
                                });
                                break;
                            }
                        }
                    }

                    if (i + 2 <= data.size() && data[i] == 'M' && data[i + 1] == 'Z') {
                        if (cur_addr > 0x10000 && cur_addr < 0x7FFFFFFFFFFF) {
                            findings.push_back({
                                {"type", "pe_header"},
                                {"address", format_utils::format_address(cur_addr)},
                                {"decoded_value", "MZ header at non-module address"},
                                {"confidence", 0.6},
                                {"encoding_key", ""}
                            });
                        }
                    }
                }
            }
        }

        return s_http_response::ok({
            {"findings", findings},
            {"count", findings.size()},
            {"scan_ranges", static_cast<int>(scan_ranges.size())}
        });
    });

    router.get("/api/config/strings", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        auto encoding = req.get_query("encoding", "utf8");
        auto limit_str = req.get_query("limit", "200");
        auto offset_str = req.get_query("offset", "0");

        int limit = format_utils::safe_parse_int(limit_str, 200);
        int offset = format_utils::safe_parse_int(offset_str, 0);
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;
        if (offset < 0) offset = 0;

        duint scan_base = 0;
        size_t scan_size = 0;
        std::string scan_module = module_name;

        if (!module_name.empty()) {
            scan_base = bridge.get_module_base(module_name);
            if (scan_base == 0) {
                return s_http_response::not_found("Module not found: " + module_name);
            }
            scan_size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
        } else {
            scan_module = bridge.get_module_at(bridge.eval_expression("cip"));
            scan_base = bridge.eval_expression("mod.base(" + scan_module + ")");
            scan_size = static_cast<size_t>(bridge.eval_expression("mod.size(" + scan_module + ")"));
        }

        if (scan_size == 0) {
            return s_http_response::ok({
                {"strings", nlohmann::json::array()},
                {"count", 0},
                {"module", scan_module}
            });
        }

        Script::Module::ModuleInfo mod_info{};
        if (Script::Module::InfoFromName(scan_module.c_str(), &mod_info)) {
            BridgeList<Script::Module::ModuleSectionInfo> sections;
            if (Script::Module::SectionListFromName(scan_module.c_str(), &sections)) {
                std::vector<std::pair<duint, size_t>> string_regions;
                for (int i = 0; i < sections.Count(); ++i) {
                    const auto& sec = sections[i];
                    if (strstr(sec.name, ".rdata") || strstr(sec.name, ".rodata") ||
                        strstr(sec.name, ".idata") || strstr(sec.name, ".text")) {
                        string_regions.emplace_back(sec.addr, static_cast<size_t>(sec.size));
                    }
                }

                if (!string_regions.empty()) {
                    auto all_strings = nlohmann::json::array();

                    for (const auto& [base, size] : string_regions) {
                        for (size_t addr = base; addr < base + size && all_strings.size() < static_cast<size_t>(offset + limit + 100); ++addr) {
                            ENCODETYPE enc = DbgGetEncodeTypeAt(addr, static_cast<duint>(std::min<size_t>(64, base + size - addr)));
                            if (enc != enc_ascii && enc != enc_unicode) continue;

                            char text[MAX_STRING_SIZE] = {};
                            bool found = DbgGetStringAt(addr, text);
                            if (!found || text[0] == '\0') continue;

                            size_t str_len = strlen(text);
                            if (str_len < 2 || str_len > 4096) continue;

                            std::string val(text);
                            bool valid = true;
                            for (char c : val) {
                                if (static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7F) continue;
                                if (c == '\r' || c == '\n' || c == '\t') continue;
                                valid = false;
                                break;
                            }
                            if (!valid) continue;

                            all_strings.push_back({
                                {"address", format_utils::format_address(addr)},
                                {"value", val},
                                {"encoding", "ascii"},
                                {"length", str_len}
                            });

                            addr += str_len;
                        }
                    }

                    int total = static_cast<int>(all_strings.size());
                    int page_start = std::min(offset, total);
                    int page_end = std::min(page_start + limit, total);

                    auto page_strings = nlohmann::json::array();
                    for (int i = page_start; i < page_end; ++i) {
                        page_strings.push_back(all_strings[i]);
                    }

                    return s_http_response::ok({
                        {"strings", page_strings},
                        {"count", page_end - page_start},
                        {"total", total},
                        {"offset", page_start},
                        {"has_more", page_end < total},
                        {"module", scan_module}
                    });
                }
            }
        }

        return s_http_response::ok({
            {"strings", nlohmann::json::array()},
            {"count", 0},
            {"module", scan_module}
        });
    });
}

} // namespace handlers
