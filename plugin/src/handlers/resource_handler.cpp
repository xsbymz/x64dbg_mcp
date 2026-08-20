#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include "_dbgfunctions.h"

namespace handlers {

#pragma pack(push, 1)
struct pe_dos_header {
    uint16_t e_magic;
    uint32_t e_cblp;
    uint32_t e_cp;
    uint32_t e_crlc;
    uint32_t e_cparhdr;
    uint32_t e_minalloc;
    uint32_t e_maxalloc;
    uint32_t e_ss;
    uint32_t e_sp;
    uint32_t e_csum;
    uint32_t e_ip;
    uint32_t e_cs;
    uint32_t e_lfarlc;
    uint32_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct pe_file_header {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct pe_data_directory {
    uint32_t virtual_address;
    uint32_t size;
};

struct pe_optional_header_64 {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    pe_data_directory export_table;
    pe_data_directory import_table;
    pe_data_directory resource_table;
    pe_data_directory exception_table;
    pe_data_directory certificate_table;
    pe_data_directory base_relocation_table;
    pe_data_directory debug;
    pe_data_directory architecture;
    pe_data_directory global_ptr;
    pe_data_directory tls_table;
    pe_data_directory load_config_table;
    pe_data_directory bound_import;
    pe_data_directory iat;
    pe_data_directory delay_import_descriptor;
    pe_data_directory clr_runtime_header;
    pe_data_directory reserved;
};

struct pe_section_header {
    uint8_t  name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
};

struct image_resource_directory {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t number_of_named_entries;
    uint16_t number_of_id_entries;
};

struct image_resource_directory_entry {
    union {
        uint32_t name;
        uint32_t id;
    };
    uint32_t offset_to_data;
};

struct image_resource_data_entry {
    uint32_t offset_to_data;
    uint32_t size;
    uint32_t code_page;
    uint32_t reserved;
};
#pragma pack(pop)

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.seekg(0, std::ios::end);
    size_t sz = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(sz);
    if (!f.read(reinterpret_cast<char*>(buf.data()), sz)) return {};
    return buf;
}

static uint32_t pe_rva_to_offset(const std::vector<uint8_t>& pe, uint64_t rva) {
    if (pe.size() < sizeof(pe_dos_header)) return 0;
    auto* dos = reinterpret_cast<const pe_dos_header*>(pe.data());
    if (dos->e_magic != 0x5A4D) return 0;
    if (pe.size() < dos->e_lfanew + sizeof(uint32_t) + sizeof(pe_file_header)) return 0;
    auto* nt = reinterpret_cast<const uint32_t*>(pe.data() + dos->e_lfanew);
    if (*nt != 0x00004550) return 0;
    auto* filehdr = reinterpret_cast<const pe_file_header*>(pe.data() + dos->e_lfanew + sizeof(uint32_t));
    bool is64 = (filehdr->size_of_optional_header == sizeof(pe_optional_header_64));
    size_t opt_size = is64 ? sizeof(pe_optional_header_64) : 0;
    size_t sections_start = dos->e_lfanew + sizeof(uint32_t) + sizeof(pe_file_header) + opt_size;
    if (pe.size() < sections_start) return 0;
    auto num_secs = filehdr->number_of_sections;
    for (size_t i = 0; i < num_secs; ++i) {
        auto* sec = reinterpret_cast<const pe_section_header*>(pe.data() + sections_start + i * sizeof(pe_section_header));
        uint32_t va = sec->virtual_address;
        uint32_t vsz = sec->virtual_size;
        if (vsz == 0) vsz = sec->size_of_raw_data;
        if (rva >= va && rva < va + vsz) {
            if (sec->pointer_to_raw_data == 0) return 0;
            return static_cast<uint32_t>(sec->pointer_to_raw_data + (rva - va));
        }
    }
    return 0;
}

static std::string resource_type_to_string(uint32_t type) {
    switch (type) {
        case 1:  return "RT_CURSOR";
        case 2:  return "RT_BITMAP";
        case 3:  return "RT_ICON";
        case 4:  return "RT_MENU";
        case 5:  return "RT_DIALOG";
        case 6:  return "RT_STRING";
        case 7:  return "RT_FONTDIR";
        case 8:  return "RT_FONT";
        case 9:  return "RT_ACCELERATOR";
        case 10: return "RT_RCDATA";
        case 11: return "RT_MESSAGETABLE";
        case 12: return "RT_GROUP_CURSOR";
        case 14: return "RT_GROUP_ICON";
        case 16: return "RT_VERSION";
        case 17: return "RT_DLGINCLUDE";
        case 19: return "RT_PLUGPLAY";
        case 20: return "RT_VXD";
        case 21: return "RT_ANICURSOR";
        case 22: return "RT_ANIICON";
        case 23: return "RT_HTML";
        case 24: return "RT_MANIFEST";
        default: return "RT_UNKNOWN(" + std::to_string(type) + ")";
    }
}

static std::string lang_to_string(uint16_t lang) {
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%04X", lang);
    return std::string(buf);
}

static void parse_resource_directory(const std::vector<uint8_t>& pe, uint64_t dir_rva,
                                     uint32_t dir_size, duint mod_base, uint32_t depth,
                                     nlohmann::json& resources, uint32_t type_hint, uint32_t id_hint) {
    if (depth > 4 || dir_size < sizeof(image_resource_directory)) return;
    uint32_t dir_offset = pe_rva_to_offset(pe, dir_rva);
    if (dir_offset == 0 || dir_offset + sizeof(image_resource_directory) > pe.size()) return;
    auto* dir = reinterpret_cast<const image_resource_directory*>(pe.data() + dir_offset);
    uint32_t total_entries = dir->number_of_named_entries + dir->number_of_id_entries;
    if (total_entries == 0) return;
    size_t entries_start = dir_offset + sizeof(image_resource_directory);
    for (uint32_t i = 0; i < total_entries; ++i) {
        if (entries_start + i * sizeof(image_resource_directory_entry) + sizeof(image_resource_directory_entry) > pe.size()) break;
        auto* entry = reinterpret_cast<const image_resource_directory_entry*>(pe.data() + entries_start + i * sizeof(image_resource_directory_entry));
        uint32_t name_or_id = entry->id;
        uint32_t child_rva = entry->offset_to_data;
        if (child_rva & 0x80000000) {
            uint32_t child_dir_rva = child_rva & 0x7FFFFFFF;
            uint32_t next_type = (depth == 0) ? (name_or_id ? name_or_id : type_hint) : type_hint;
            uint32_t next_id = (depth == 1) ? name_or_id : id_hint;
            parse_resource_directory(pe, child_dir_rva, dir_size, mod_base, depth + 1, resources, next_type, next_id);
        } else {
            uint32_t data_offset = pe_rva_to_offset(pe, child_rva);
            if (data_offset != 0 && data_offset + sizeof(image_resource_data_entry) <= pe.size()) {
                auto* data_entry = reinterpret_cast<const image_resource_data_entry*>(pe.data() + data_offset);
                duint data_va = mod_base + data_entry->offset_to_data;
                uint32_t size = data_entry->size;
                uint32_t lang = (depth == 2) ? name_or_id : 0;
                resources.push_back({
                    {"type", resource_type_to_string(type_hint)},
                    {"name", type_hint == 0 ? "UNKNOWN" : (name_or_id ? "ID_" + std::to_string(name_or_id) : "ID_0")},
                    {"id", id_hint},
                    {"language", lang_to_string(lang)},
                    {"size", size},
                    {"virtual_address", format_utils::format_address(data_va)}
                });
            }
        }
    }
}

static std::string base64_encode(const uint8_t* data, size_t len) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out.push_back(b64[(triple >> 18) & 0x3F]);
        out.push_back(b64[(triple >> 12) & 0x3F]);
        out.push_back(b64[(triple >> 6) & 0x3F]);
        out.push_back(b64[triple & 0x3F]);
    }
    for (size_t j = 0; j < (3 - len % 3) % 3; ++j) out.push_back('=');
    return out;
}

void register_resource_routes(c_http_router& router) {
    router.get("/api/resources/list", [](const s_http_request& req) -> s_http_response {
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

        char path[MAX_PATH] = {};
        if (DbgFunctions()->ModPathFromName(module.c_str(), path, sizeof(path)) == 0) {
            return s_http_response::internal_error("Failed to get module path");
        }

        auto pe = read_file(path);
        if (pe.empty()) {
            return s_http_response::internal_error("Failed to read module from disk");
        }

        if (pe.size() < sizeof(pe_dos_header)) {
            return s_http_response::internal_error("Invalid PE file");
        }
        auto* dos = reinterpret_cast<const pe_dos_header*>(pe.data());
        if (dos->e_magic != 0x5A4D) {
            return s_http_response::internal_error("Invalid DOS signature");
        }
        if (pe.size() < dos->e_lfanew + sizeof(uint32_t) + sizeof(pe_file_header) + sizeof(pe_optional_header_64)) {
            return s_http_response::internal_error("Invalid PE header size");
        }
        auto* nt = reinterpret_cast<const uint32_t*>(pe.data() + dos->e_lfanew);
        if (*nt != 0x00004550) {
            return s_http_response::internal_error("Invalid NT signature");
        }
        auto* filehdr = reinterpret_cast<const pe_file_header*>(pe.data() + dos->e_lfanew + sizeof(uint32_t));
        bool is64 = (filehdr->size_of_optional_header == sizeof(pe_optional_header_64));
        auto* opt = reinterpret_cast<const pe_optional_header_64*>(pe.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(pe_file_header));
        if (!is64) {
            return s_http_response::internal_error("Only 64-bit PE supported");
        }
        if (opt->number_of_rva_and_sizes < 3) {
            return s_http_response::internal_error("No resource directory");
        }

        auto resources = nlohmann::json::array();
        parse_resource_directory(pe, opt->resource_table.virtual_address, opt->resource_table.size, mod_base, 0, resources, 0, 0);

        return s_http_response::ok({
            {"module", module},
            {"resources", resources},
            {"count", resources.size()}
        });
    });

    router.get("/api/resources/extract", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module", "");
        auto id_str = req.get_query("id", "");
        auto type_str = req.get_query("type", "");
        if (module.empty() || id_str.empty() || type_str.empty()) {
            return s_http_response::bad_request("Missing 'module', 'id', or 'type' query parameter");
        }

        auto mod_base = bridge.get_module_base(module);
        if (mod_base == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        char path[MAX_PATH] = {};
        if (DbgFunctions()->ModPathFromName(module.c_str(), path, sizeof(path)) == 0) {
            return s_http_response::internal_error("Failed to get module path");
        }

        auto pe = read_file(path);
        if (pe.empty()) {
            return s_http_response::internal_error("Failed to read module from disk");
        }
        if (pe.size() < sizeof(pe_dos_header)) {
            return s_http_response::internal_error("Invalid PE file");
        }
        auto* dos = reinterpret_cast<const pe_dos_header*>(pe.data());
        if (dos->e_magic != 0x5A4D) return s_http_response::internal_error("Invalid DOS signature");
        auto* filehdr = reinterpret_cast<const pe_file_header*>(pe.data() + dos->e_lfanew + sizeof(uint32_t));
        bool is64 = (filehdr->size_of_optional_header == sizeof(pe_optional_header_64));
        auto* opt = reinterpret_cast<const pe_optional_header_64*>(pe.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(pe_file_header));
        if (!is64) return s_http_response::internal_error("Only 64-bit PE supported");

        uint32_t target_type = std::stoul(type_str, nullptr, 10);
        uint32_t target_id = std::stoul(id_str, nullptr, 10);

        auto* dir = reinterpret_cast<const image_resource_directory*>(pe.data() + pe_rva_to_offset(pe, opt->resource_table.virtual_address));
        if (!dir) return s_http_response::not_found("Resource directory not found");

        uint32_t total_entries = dir->number_of_named_entries + dir->number_of_id_entries;
        size_t entries_start = pe_rva_to_offset(pe, opt->resource_table.virtual_address) + sizeof(image_resource_directory);
        for (uint32_t i = 0; i < total_entries; ++i) {
            auto* entry = reinterpret_cast<const image_resource_directory_entry*>(pe.data() + entries_start + i * sizeof(image_resource_directory_entry));
            if (entry->id != target_type) continue;
            uint32_t child_rva = entry->offset_to_data & 0x7FFFFFFF;
            auto* child_dir = reinterpret_cast<const image_resource_directory*>(pe.data() + pe_rva_to_offset(pe, child_rva));
            if (!child_dir) continue;
            uint32_t ctotal = child_dir->number_of_named_entries + child_dir->number_of_id_entries;
            size_t centries = pe_rva_to_offset(pe, child_rva) + sizeof(image_resource_directory);
            for (uint32_t j = 0; j < ctotal; ++j) {
                auto* centry = reinterpret_cast<const image_resource_directory_entry*>(pe.data() + centries + j * sizeof(image_resource_directory_entry));
                if (centry->id != target_id) continue;
                uint32_t data_rva = centry->offset_to_data;
                auto* data_entry = reinterpret_cast<const image_resource_data_entry*>(pe.data() + pe_rva_to_offset(pe, data_rva));
                if (!data_entry) continue;
                duint data_va = mod_base + data_entry->offset_to_data;
                uint32_t size = data_entry->size;
                auto mem = bridge.read_memory(data_va, size);
                if (!mem.has_value()) {
                    return s_http_response::internal_error("Failed to read resource data from memory");
                }
                std::string b64 = base64_encode(mem->data(), mem->size());
                return s_http_response::ok({
                    {"module", module},
                    {"id", target_id},
                    {"type", target_type},
                    {"data", b64},
                    {"size", size},
                    {"language", 0}
                });
            }
        }
        return s_http_response::not_found("Resource not found");
    });
}

} // namespace handlers
