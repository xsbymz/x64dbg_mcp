#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <cstring>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

namespace {

bool read_pe_section_headers(c_bridge_executor& bridge, duint base, WORD& num_sections, duint& section_offset) {
    auto dos = bridge.read_memory(base, 64);
    if (!dos.has_value() || dos->size() < 64 || (*dos)[0] != 'M' || (*dos)[1] != 'Z') {
        return false;
    }

    DWORD e_lfanew = 0;
    std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);

    auto pe = bridge.read_memory(base + e_lfanew, 24);
    if (!pe.has_value() || pe->size() < 24 || (*pe)[0] != 'P' || (*pe)[1] != 'E') {
        return false;
    }

    std::memcpy(&num_sections, pe->data() + 6, 2);
    WORD optional_size = 0;
    std::memcpy(&optional_size, pe->data() + 20, 2);

    section_offset = e_lfanew + 24 + optional_size;
    return true;
}

struct pe_section_info {
    std::string name;
    duint virtual_address;
    duint virtual_size;
    duint raw_size;
    duint characteristics;
    bool is_executable;
};

std::vector<pe_section_info> get_module_sections(c_bridge_executor& bridge, duint base) {
    std::vector<pe_section_info> sections;
    WORD num_sections = 0;
    duint section_offset = 0;
    if (!read_pe_section_headers(bridge, base, num_sections, section_offset)) {
        return sections;
    }

    auto section_data = bridge.read_memory(base + section_offset, num_sections * 40);
    if (!section_data.has_value()) {
        return sections;
    }

    for (WORD i = 0; i < num_sections; ++i) {
        auto* sec = section_data.value().data() + (i * 40);
        pe_section_info info;
        char name[9] = {};
        std::memcpy(name, sec, 8);
        info.name = name;
        std::memcpy(&info.virtual_size, sec + 8, 4);
        std::memcpy(&info.virtual_address, sec + 12, 4);
        std::memcpy(&info.raw_size, sec + 16, 4);
        std::memcpy(&info.characteristics, sec + 36, 4);
        info.is_executable = (info.characteristics & 0x20000000) != 0;
        sections.push_back(info);
    }

    return sections;
}

std::vector<uint8_t> read_file_bytes(const std::string& path) {
    std::vector<uint8_t> data;
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || f == nullptr) {
        return data;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size <= 0) {
        fclose(f);
        return data;
    }

    fseek(f, 0, SEEK_SET);
    data.resize(static_cast<size_t>(size));
    size_t read = fread(data.data(), 1, static_cast<size_t>(size), f);
    fclose(f);
    data.resize(read);
    return data;
}

} // namespace

void register_diffing_routes(c_http_router& router) {
    // POST /api/diff/memory_vs_disk - Compare in-memory module against on-disk image
    router.post("/api/diff/memory_vs_disk", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("module")) {
            return s_http_response::bad_request("Missing 'module' field");
        }

        auto module_name = body["module"].get<std::string>();
        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        char disk_path[MAX_PATH] = {};
        if (!DbgFunctions()->ModPathFromName(module_name.c_str(), disk_path, sizeof(disk_path))) {
            return s_http_response::internal_error("Failed to get module disk path");
        }

        auto disk_bytes = read_file_bytes(disk_path);
        if (disk_bytes.empty()) {
            return s_http_response::internal_error("Failed to read module file from disk");
        }

        auto mem_sections = get_module_sections(bridge, base);
        if (mem_sections.empty()) {
            return s_http_response::internal_error("Failed to read module sections");
        }

        auto differences = nlohmann::json::array();
        size_t total_differences = 0;
        size_t total_compared = 0;
        auto packed_sections = nlohmann::json::array();

        for (const auto& sec : mem_sections) {
            duint mem_start = base + sec.virtual_address;
            size_t mem_size = static_cast<size_t>(sec.virtual_size);
            if (mem_size == 0) continue;

            auto mem_bytes = bridge.read_memory(mem_start, mem_size);
            if (!mem_bytes.has_value()) continue;

            size_t sec_diffs = 0;
            size_t compare_size = std::min<size_t>(mem_bytes.value().size(), disk_bytes.size() > static_cast<size_t>(sec.virtual_address) ? disk_bytes.size() - static_cast<size_t>(sec.virtual_address) : 0);

            for (size_t i = 0; i < compare_size && i < mem_bytes.value().size(); ++i) {
                uint8_t mem_byte = mem_bytes.value()[i];
                uint8_t disk_byte = (sec.virtual_address + i < disk_bytes.size()) ? disk_bytes[static_cast<size_t>(sec.virtual_address) + i] : 0x00;

                if (mem_byte != disk_byte) {
                    sec_diffs++;
                    total_differences++;
                    differences.push_back({
                        {"address",          format_utils::format_address(mem_start + i)},
                        {"memory_byte",      format_utils::format_hex(mem_byte)},
                        {"disk_byte",        format_utils::format_hex(disk_byte)},
                        {"is_executable_section", sec.is_executable}
                    });
                }
            }

            total_compared += compare_size;

            if (mem_size > 0 && sec_diffs * 100 / mem_size > 30) {
                packed_sections.push_back({
                    {"name", sec.name},
                    {"difference_percent", static_cast<int>(sec_diffs * 100 / mem_size)}
                });
            }
        }

        double similarity = total_compared > 0 ? 100.0 - (total_differences * 100.0 / total_compared) : 100.0;
        if (similarity < 0.0) similarity = 0.0;
        if (similarity > 100.0) similarity = 100.0;

        return s_http_response::ok({
            {"module",             module_name},
            {"base_address",       format_utils::format_address(base)},
            {"disk_path",          std::string(disk_path)},
            {"differences",        differences},
            {"total_differences",  total_differences},
            {"similarity_percentage", similarity},
            {"packed_sections",    packed_sections}
        });
    });

    // POST /api/diff/pe_sections - Compare two module sections
    router.post("/api/diff/pe_sections", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("module1") || !body.contains("module2")) {
            return s_http_response::bad_request("Missing 'module1' and/or 'module2' fields");
        }

        auto module1 = body["module1"].get<std::string>();
        auto module2 = body["module2"].get<std::string>();
        auto base1 = bridge.get_module_base(module1);
        auto base2 = bridge.get_module_base(module2);

        if (base1 == 0) return s_http_response::not_found("Module1 not found: " + module1);
        if (base2 == 0) return s_http_response::not_found("Module2 not found: " + module2);

        auto secs1 = get_module_sections(bridge, base1);
        auto secs2 = get_module_sections(bridge, base2);

        if (secs1.empty() || secs2.empty()) {
            return s_http_response::internal_error("Failed to read sections");
        }

        size_t total_bytes = 0;
        size_t matching_bytes = 0;
        auto differing_offsets = nlohmann::json::array();

        size_t max_sections = std::min(secs1.size(), secs2.size());
        for (size_t i = 0; i < max_sections; ++i) {
            size_t cmp_size = std::min<size_t>(static_cast<size_t>(secs1[i].virtual_size), static_cast<size_t>(secs2[i].virtual_size));
            if (cmp_size == 0) continue;

            auto mem1 = bridge.read_memory(base1 + secs1[i].virtual_address, cmp_size);
            auto mem2 = bridge.read_memory(base2 + secs2[i].virtual_address, cmp_size);
            if (!mem1.has_value() || !mem2.has_value()) continue;

            for (size_t j = 0; j < cmp_size; ++j) {
                total_bytes++;
                if (mem1.value()[j] == mem2.value()[j]) {
                    matching_bytes++;
                } else if (differing_offsets.size() < 10000) {
                    differing_offsets.push_back({
                        {"offset", static_cast<int>(j)},
                        {"bytes1", format_utils::format_bytes_hex(&mem1.value()[j], 1)},
                        {"bytes2", format_utils::format_bytes_hex(&mem2.value()[j], 1)}
                    });
                }
            }
        }

        int match_score = total_bytes > 0 ? static_cast<int>(matching_bytes * 100 / total_bytes) : 0;

        return s_http_response::ok({
            {"module1",           module1},
            {"module2",           module2},
            {"match_score",       match_score},
            {"total_bytes",       total_bytes},
            {"matching_bytes",    matching_bytes},
            {"differing_offsets", differing_offsets}
        });
    });

    // GET /api/diff/patches - List all current patches
    router.get("/api/diff/patches", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        size_t count = 0;
        DbgFunctions()->PatchEnum(nullptr, &count);

        auto patches = nlohmann::json::array();
        if (count > 0) {
            std::vector<DBGPATCHINFO> list(count);
            DbgFunctions()->PatchEnum(list.data(), &count);
            for (size_t i = 0; i < count; ++i) {
                patches.push_back({
                    {"address",  format_utils::format_address(list[i].addr)},
                    {"old_byte", format_utils::format_bytes_compact(&list[i].oldbyte, 1)},
                    {"new_byte", format_utils::format_bytes_compact(&list[i].newbyte, 1)},
                    {"module",   std::string(list[i].mod)}
                });
            }
        }

        return s_http_response::ok({
            {"patches", patches},
            {"count",   patches.size()}
        });
    });
}

} // namespace handlers
