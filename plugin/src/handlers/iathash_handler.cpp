#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <cstdint>
#include <cstring>
#include "_dbgfunctions.h"

namespace handlers {

static uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}

static uint64_t fnv1a64(const uint8_t* data, size_t len) {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

void register_iathash_routes(c_http_router& router) {
    router.get("/api/iathash", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module", "");
        if (module.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto mod_base = bridge.get_module_base(module);
        if (mod_base == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        nlohmann::json imports = nlohmann::json::array();
        auto import_result = bridge.get_memory_map();
        if (!import_result.has_value()) {
            return s_http_response::internal_error(import_result.error());
        }

        size_t entry_count = 0;
        std::vector<uint64_t> iat_addrs;
        for (const auto& page : import_result.value()) {
            auto info = page.value("info", "");
            if (info.find("import") == std::string::npos) continue;
            auto base_str = page.value("base", "0");
            duint base = format_utils::parse_address(base_str);
            auto size = page.value("size", 0);
            auto mem = bridge.read_memory(base, size);
            if (!mem.has_value()) continue;
            const uint8_t* bytes = mem->data();
            size_t count = mem->size() / sizeof(uint64_t);
            for (size_t i = 0; i < count; ++i) {
                uint64_t addr = 0;
                memcpy(&addr, bytes + i * sizeof(uint64_t), sizeof(uint64_t));
                if (addr != 0 && entry_count < 10) {
                    std::string mod_name = bridge.get_module_at(addr);
                    std::string func_name = "";
                    if (!mod_name.empty()) {
                        func_name = bridge.get_label_at(addr);
                    }
                    imports.push_back({
                        {"dll", mod_name},
                        {"function", func_name},
                        {"address", format_utils::format_address(addr)}
                    });
                }
                iat_addrs.push_back(addr);
                entry_count++;
            }
        }

        std::vector<uint8_t> hash_buf;
        hash_buf.reserve(iat_addrs.size() * sizeof(uint64_t));
        for (auto a : iat_addrs) {
            uint64_t le = a;
            hash_buf.insert(hash_buf.end(), reinterpret_cast<uint8_t*>(&le), reinterpret_cast<uint8_t*>(&le) + sizeof(uint64_t));
        }

        uint32_t iat_crc32 = crc32(hash_buf.data(), hash_buf.size());
        uint64_t iat_xxhash = fnv1a64(hash_buf.data(), hash_buf.size());

        return s_http_response::ok({
            {"module", module},
            {"iat_crc32", iat_crc32},
            {"iat_xxhash", iat_xxhash},
            {"entry_count", entry_count},
            {"first_10_imports", imports}
        });
    });

    router.get("/api/eathash", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module", "");
        if (module.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto mod_base = bridge.get_module_base(module);
        if (mod_base == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        auto export_info = bridge.eval_expression("mod.exp(" + module + ")");
        uint32_t export_count = 0;
        std::vector<uint64_t> eat_addrs;

        auto memmap = bridge.get_memory_map();
        if (memmap.has_value()) {
            for (const auto& page : memmap.value()) {
                auto info = page.value("info", "");
                if (info.find("export") == std::string::npos) continue;
                auto base_str = page.value("base", "0");
                duint base = format_utils::parse_address(base_str);
                auto size = page.value("size", 0);
                auto mem = bridge.read_memory(base, size);
                if (!mem.has_value()) continue;
                const uint8_t* bytes = mem->data();
                size_t count = mem->size() / sizeof(uint64_t);
                for (size_t i = 0; i < count; ++i) {
                    uint64_t addr = 0;
                    memcpy(&addr, bytes + i * sizeof(uint64_t), sizeof(uint64_t));
                    if (addr != 0) {
                        eat_addrs.push_back(addr);
                        export_count++;
                    }
                }
            }
        }

        std::vector<uint8_t> hash_buf;
        hash_buf.reserve(eat_addrs.size() * sizeof(uint64_t));
        for (auto a : eat_addrs) {
            uint64_t le = a;
            hash_buf.insert(hash_buf.end(), reinterpret_cast<uint8_t*>(&le), reinterpret_cast<uint8_t*>(&le) + sizeof(uint64_t));
        }

        uint32_t eat_crc32 = crc32(hash_buf.data(), hash_buf.size());
        uint64_t eat_xxhash = fnv1a64(hash_buf.data(), hash_buf.size());

        return s_http_response::ok({
            {"module", module},
            {"eat_crc32", eat_crc32},
            {"eat_xxhash", eat_xxhash},
            {"export_count", export_count}
        });
    });
}

} // namespace handlers
