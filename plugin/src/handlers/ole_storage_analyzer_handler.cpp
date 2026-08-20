#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_ole_storage_analyzer_routes(c_http_router& router) {
    router.post("/api/ole_storage/parse_compound_file", [](const httplib::Request& req, httplib::Response& res) {
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
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/ole_storage/enumerate_streams", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["standard_stream_names"] = {
            {"\\x05SummaryInformation", "Metadata: Author, LastSavedBy, Revision, Application"},
            {"\\x05DocumentSummaryInformation", "Company, Category, Security flags"},
            {"WordDocument", "Main Word 97-2003 binary document stream"},
            {"Workbook / Book", "Excel 97-2003 binary workbook stream"},
            {"VBA / _VBA_PROJECT", "Embedded VBA macro project code streams"},
            {"\\x01Ole10Native", "Embedded native binary payload / dropped executable"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/ole_storage/detect_exploit_patterns", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["ole_exploit_threats"] = {
            {"Equation_Editor_CVE-2017-11882", "Embedded Equation3 CLSID {0002CE02-0000-0000-C000-000000000046} with font record buffer overflow"},
            {"VBA_Purging", "PerformanceCache compiled P-code present while source VBA compressed source code is removed (evades static AV regex)"},
            {"Embedded_Package_Payload", "Ole10Native stream containing PE file (MZ/PE) extracted via packager.dll"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
