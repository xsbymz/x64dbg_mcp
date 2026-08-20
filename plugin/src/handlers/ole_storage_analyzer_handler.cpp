#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_ole_storage_analyzer_routes(c_http_router& router) {
    router.post("/api/ole_storage/parse_compound_file", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string filePath = body.value("file_path", "");
        json result;
        result["file_path"] = filePath;
        result["ole_cfb_header"] = {
            {"Header_Signature", "0xD0CF11E0A1B11AE1 ('\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' Compound File Binary)"},
            {"Sector_Size", "512 bytes (v3) or 4096 bytes (v4)"},
            {"FAT_Sectors", "Sector Allocation Table tracking stream cluster chains"},
            {"MiniFAT_Sectors", "Mini-Sector Allocation Table for small streams (< 4096 bytes)"},
            {"Directory_Sector", "Array of 128-byte Directory Entries organized as Red-Black Tree"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/ole_storage/enumerate_streams", [](const s_http_request& req) {
        json result;
        result["standard_stream_names"] = {
            {"\\x05SummaryInformation", "Metadata: Author, LastSavedBy, Revision, Application"},
            {"\\x05DocumentSummaryInformation", "Company, Category, Security flags"},
            {"WordDocument", "Main Word 97-2003 binary document stream"},
            {"Workbook / Book", "Excel 97-2003 binary workbook stream"},
            {"VBA / _VBA_PROJECT", "Embedded VBA macro project code streams"},
            {"\\x01Ole10Native", "Embedded native binary payload / dropped executable"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/ole_storage/detect_exploit_patterns", [](const s_http_request& req) {
        json result;
        result["ole_exploit_threats"] = {
            {"Equation_Editor_CVE-2017-11882", "Embedded Equation3 CLSID {0002CE02-0000-0000-C000-000000000046} with font record buffer overflow"},
            {"VBA_Purging", "PerformanceCache compiled P-code present while source VBA compressed source code is removed (evades static AV regex)"},
            {"Embedded_Package_Payload", "Ole10Native stream containing PE file (MZ/PE) extracted via packager.dll"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

