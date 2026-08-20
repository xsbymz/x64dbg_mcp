#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <sddl.h>
using json = nlohmann::json;

namespace handlers {
void register_sd_dacl_evaluator_routes(c_http_router& router) {
    router.post("/api/sd_eval/evaluate_access_mask", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string sddl = body.value("sddl_string", "D:(A;;GA;;;WD)");
        json result;
        result["sddl_string"] = sddl;
        result["access_evaluation_model"] = {
            {"DACL_Traversal", "DACL ACEs evaluated in strict top-down order until requested access is fully granted or explicitly denied"},
            {"ACCESS_DENIED_ACE", "Type 0x01 (Deny ACE takes precedence if positioned before Allow ACE)"},
            {"ACCESS_ALLOWED_ACE", "Type 0x00 (Accumulates granted access rights in RemainingDesiredAccess mask)"},
            {"Mandatory_Integrity", "SYSTEM_MANDATORY_LABEL_ACE (S-1-16-0x1000 Low, 0x2000 Medium, 0x3000 High, 0x4000 System)"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/sd_eval/parse_sddl", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string sddl = body.value("sddl", "O:SYG:SYD:(A;;0x1fffff;;;WD)");
        json result;
        result["sddl"] = sddl;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        ULONG sdSize = 0;
        std::wstring wsddl(sddl.begin(), sddl.end());
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(wsddl.c_str(), SDDL_REVISION_1, &pSD, &sdSize)) {
            result["valid"] = true;
            result["descriptor_size"] = sdSize;
            LocalFree(pSD);
        } else {
            result["valid"] = false;
            result["error_code"] = (int)GetLastError();
        }
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
