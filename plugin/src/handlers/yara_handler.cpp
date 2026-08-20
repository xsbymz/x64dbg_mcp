#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <cmath>
#include <iomanip>
#include <sstream>
#include <random>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static double shannon_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;

    int frequencies[256] = {0};
    for (size_t i = 0; i < size; ++i) {
        frequencies[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (frequencies[i] > 0) {
            double p = static_cast<double>(frequencies[i]) / size;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

static std::string escape_yara_string(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '\\': result += "\\\\"; break;
            case '\"': result += "\\\""; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            case '\0': result += "\\0"; break;
            default:
                if (static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7F) {
                    result += c;
                } else {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\x%02X", static_cast<unsigned char>(c));
                    result += buf;
                }
                break;
        }
    }
    return result;
}

static std::string generate_uuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) ss << std::setw(1) << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << std::setw(1) << dis(gen);
    ss << "-";
    ss << std::setw(1) << dis2(gen);
    for (int i = 0; i < 3; ++i) ss << std::setw(1) << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << std::setw(1) << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; ++i) ss << std::setw(1) << dis(gen);
    return ss.str();
}

void register_yara_routes(c_http_router& router) {
    router.post("/api/yara/from_memory", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("size")) {
            return s_http_response::bad_request("Missing 'address' and/or 'size' fields");
        }

        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint address;
        if (body["address"].is_string()) {
            address = bridge.eval_expression(body["address"].get<std::string>());
        } else if (body["address"].is_number_unsigned()) {
            address = body["address"].get<duint>();
        } else {
            return s_http_response::bad_request("Invalid address format");
        }

        size_t size = body["size"].get<size_t>();
        std::string rule_name = body.value("rule_name", "generated_rule");
        bool strings_only = body.value("strings_only", false);

        if (address == 0 || size == 0) {
            return s_http_response::bad_request("Invalid address or size");
        }

        if (size > 16 * 1024 * 1024) {
            return s_http_response::bad_request("Size exceeds 16 MB limit");
        }

        auto mem_result = bridge.read_memory(address, size);
        if (!mem_result.has_value()) {
            return s_http_response::internal_error(mem_result.error());
        }

        const auto& mem = mem_result.value();
        std::vector<std::pair<std::string, std::string>> found_strings;
        std::string current;
        for (size_t i = 0; i < mem.size(); ++i) {
            uint8_t b = mem[i];
            if (b >= 0x20 && b < 0x7F) {
                current += static_cast<char>(b);
            } else {
                if (current.size() >= 4) {
                    found_strings.emplace_back(current, "ascii");
                }
                current.clear();
            }
        }
        if (current.size() >= 4) {
            found_strings.emplace_back(current, "ascii");
        }

        std::string u16_current;
        for (size_t i = 0; i + 1 < mem.size(); i += 2) {
            uint8_t lo = mem[i];
            uint8_t hi = mem[i + 1];
            if (lo >= 0x20 && lo < 0x7F && hi == 0x00) {
                u16_current += static_cast<char>(lo);
            } else {
                if (u16_current.size() >= 4) {
                    found_strings.emplace_back(u16_current, "wide");
                }
                u16_current.clear();
            }
        }
        if (u16_current.size() >= 4) {
            found_strings.emplace_back(u16_current, "wide");
        }

        std::vector<std::pair<size_t, std::string>> byte_patterns;
        if (!strings_only) {
            constexpr size_t window_size = 16;
            constexpr double entropy_threshold = 7.0;
            for (size_t i = 0; i + window_size <= mem.size(); i += window_size / 2) {
                double ent = shannon_entropy(&mem[i], window_size);
                if (ent >= entropy_threshold) {
                    std::string hex_pattern;
                    for (size_t j = 0; j < window_size && i + j < mem.size(); ++j) {
                        char buf[4];
                        snprintf(buf, sizeof(buf), "%02X", mem[i + j]);
                        hex_pattern += buf;
                    }
                    byte_patterns.emplace_back(i, hex_pattern);
                }
            }
        }

        constexpr size_t max_strings = 64;
        constexpr size_t max_patterns = 32;
        if (found_strings.size() > max_strings) {
            found_strings.resize(max_strings);
        }
        if (byte_patterns.size() > max_patterns) {
            byte_patterns.resize(max_patterns);
        }

        std::ostringstream rule;
        rule << "rule " << rule_name << "\n{\n";
        rule << "    strings:\n";

        size_t idx = 0;
        size_t ascii_count = 0;
        size_t wide_count = 0;
        for (const auto& [s, encoding] : found_strings) {
            if (encoding == "wide") {
                rule << "        $" << static_cast<char>('a' + idx) << " = \"" << escape_yara_string(s) << "\" wide\n";
                wide_count++;
            } else {
                rule << "        $" << static_cast<char>('a' + idx) << " = \"" << escape_yara_string(s) << "\" ascii\n";
                ascii_count++;
            }
            idx++;
        }
        for (const auto& [offset, pattern] : byte_patterns) {
            rule << "        $" << static_cast<char>('a' + idx) << " = { " << pattern << " }\n";
            idx++;
        }

        rule << "    condition:\n";
        if (idx == 0) {
            rule << "        false\n";
        } else if (idx == 1) {
            rule << "        $a\n";
        } else {
            rule << "        ";
            for (size_t i = 0; i < idx; ++i) {
                if (i > 0) rule << " or ";
                rule << "$" << static_cast<char>('a' + i);
            }
            rule << "\n";
        }

        rule << "}\n";

        return s_http_response::ok({
            {"rule", rule.str()},
            {"ascii_string_count", ascii_count},
            {"wide_string_count", wide_count},
            {"pattern_count", byte_patterns.size()}
        });
    });

    router.post("/api/yara/from_behavior", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("apis") || !body["apis"].is_array()) {
            return s_http_response::bad_request("Missing 'apis' array");
        }

        std::string rule_title = body.value("rule_title", "Generated Sigma Rule");

        std::unordered_map<std::string, std::string> api_categories = {
            {"CreateFileW", "file_creation"},
            {"CreateFileA", "file_creation"},
            {"WriteFile", "file_modification"},
            {"RegSetValueEx", "registry_modification"},
            {"RegCreateKeyEx", "registry_creation"},
            {"RegOpenKeyEx", "registry_access"},
            {"VirtualAlloc", "memory_allocation"},
            {"VirtualProtect", "memory_protection_change"},
            {"CreateRemoteThread", "remote_thread_creation"},
            {"SetWindowsHookEx", "hook_installation"},
            {"URLDownloadToFile", "download"},
            {"InternetOpenUrl", "network_connection"},
            {"WSAStartup", "network_initialization"},
            {"socket", "network_socket"},
            {"connect", "network_connection"},
            {"CryptEncrypt", "crypto_operation"},
            {"CryptDecrypt", "crypto_operation"},
            {"Process32First", "process_enumeration"},
            {"Process32Next", "process_enumeration"},
            {"EnumProcesses", "process_enumeration"},
            {"NtQuerySystemInformation", "system_information"},
            {"LdrLoadDll", "dll_loading"},
            {"GetProcAddress", "function_resolution"},
            {"CreateThread", "thread_creation"},
            {"NtCreateThreadEx", "thread_creation"},
            {"WriteProcessMemory", "process_memory_write"},
            {"ReadProcessMemory", "process_memory_read"},
            {"OpenProcess", "process_open"},
            {"TerminateProcess", "process_termination"},
            {"DeleteFile", "file_deletion"},
            {"CopyFile", "file_copy"}
        };

        std::unordered_map<std::string, std::vector<std::string>> categorized;
        auto& apis = body["apis"];
        for (const auto& api : apis) {
            if (api.is_string()) {
                std::string name = api.get<std::string>();
                auto it = api_categories.find(name);
                std::string cat = (it != api_categories.end()) ? it->second : "unknown";
                categorized[cat].push_back(name);
            }
        }

        std::ostringstream sigma;
        sigma << "title: " << rule_title << "\n";
        sigma << "id: " << generate_uuid() << "\n";
        sigma << "status: experimental\n";
        sigma << "description: Generated Sigma rule from observed API calls via x64dbg MCP\n";
        sigma << "author: x64dbg_mcp\n";
        sigma << "date: " << __DATE__ << "\n";
        sigma << "modified: " << __DATE__ << "\n";
        sigma << "tags:\n";
        sigma << "    - attack.defense_evasion\n";
        sigma << "    - attack.execution\n";
        sigma << "logsource:\n";
        sigma << "    product: windows\n";
        sigma << "    service: sysmon\n";
        sigma << "detection:\n";
        sigma << "    selection:\n";

        int sel_idx = 0;
        for (const auto& [cat, apis_in_cat] : categorized) {
            sigma << "        selection" << sel_idx << ":\n";
            sigma << "            Image|contains:\n";
            for (const auto& name : apis_in_cat) {
                sigma << "                - '" << name << ".dll'\n";
            }
            sigma << "\n";
            sel_idx++;
        }

        sigma << "    condition: ";
        if (sel_idx == 0) {
            sigma << "false\n";
        } else if (sel_idx == 1) {
            sigma << "selection0\n";
        } else {
            for (int i = 0; i < sel_idx; ++i) {
                if (i > 0) sigma << " or ";
                sigma << "selection" << i;
            }
            sigma << "\n";
        }

        size_t total_apis = 0;
        for (const auto& [cat, apis_in_cat] : categorized) {
            total_apis += apis_in_cat.size();
        }

        return s_http_response::ok({
            {"sigma", sigma.str()},
            {"api_count", total_apis}
        });
    });
}

} // namespace handlers
