#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <mscat.h>
#pragma comment(lib, "wintrust.lib")
using json = nlohmann::json;

namespace handlers {
void register_catalog_db_lookup_routes(c_http_router& router) {
    router.post("/api/catalog_db/query_by_hash", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string hashHex = body.value("file_hash_sha256", "");
        json result;
        result["file_hash_sha256"] = hashHex;
        result["catalog_database_architecture"] = {
            {"CatRoot", "%SystemRoot%\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"},
            {"CatRoot2", "%SystemRoot%\\System32\\CatRoot2 (Database cache containing catdb)"},
            {"CryptCATAdminAcquireContext", "Initializes catalog administrator handle"},
            {"CryptCATAdminEnumCatalogFromHash", "Searches all system security catalogs for matching member hash"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/catalog_db/enumerate_system_catalogs", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["system_catalog_files"] = json::array();
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(L"C:\\Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\*.cat", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            int count = 0;
            do {
                if (count++ < 25) {
                    char nameA[MAX_PATH] = {};
                    WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nameA, sizeof(nameA), nullptr, nullptr);
                    json entry; entry["catalog"] = std::string(nameA); entry["size"] = (DWORD)fd.nFileSizeLow;
                    result["system_catalog_files"].push_back(entry);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        result["total_displayed"] = result["system_catalog_files"].size();
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
