#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_dwarf_debug_parser_routes(c_http_router& router) {
    router.post("/api/dwarf/parse_sections", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["dwarf_pe_sections"] = {
            {".debug_info", "Compilation Unit (CU) headers, DIE (Debugging Information Entry) tags, attribute forms"},
            {".debug_abbrev", "Abbreviations table defining attribute layouts for DIE tags"},
            {".debug_line", "Line Number Program mapping machine code RVAs to source file and line numbers"},
            {".debug_str", "String table containing identifier names, source paths, and compiler versions"},
            {".debug_loc", "Location lists for variable storage across register allocation lifespans"},
            {".debug_ranges", "Non-contiguous code address ranges for functions and lexical blocks"},
            {".eh_frame", "Call Frame Information (CFI) DWARF unwinding tables used on MinGW/GCC x64"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/dwarf/extract_compilation_units", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["cu_header_format"] = {
            {"unit_length", "32-bit (DWARF-32) or 64-bit length of compilation unit"},
            {"version", "DWARF format version (2, 3, 4, or 5)"},
            {"unit_type", "DW_UT_compile (0x01), DW_UT_type (0x02), DW_UT_partial (0x03)"},
            {"abbrev_offset", "Offset into .debug_abbrev section"},
            {"address_size", "Target architecture pointer size (8 for x64, 4 for x86)"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
