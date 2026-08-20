#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_minifilter_driver_routes(c_http_router& router) {
    router.post("/api/minifilter/enumerate_filters", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["fltmgr_architecture"] = {
            {"Filter_Manager", "FltMgr.sys manages filesystem minifilter driver stack"},
            {"Altitude_Hierarchy", "Deterministic ordering of filter execution based on numeric altitude string"},
            {"Callbacks", "PFLT_PRE_OPERATION_CALLBACK and PFLT_POST_OPERATION_CALLBACK per IRP_MJ_*"}
        };
        result["standard_altitude_ranges"] = {
            {"400000-409999", "Filter (Top of stack)"},
            {"360000-389999", "Activity Monitor"},
            {"320000-329999", "Anti-Virus (EDR / Defender / Symantec / CrowdStrike)"},
            {"260000-269999", "Continuous Backup / Replication"},
            {"220000-229999", "Encryption / DRM"},
            {"180000-189999", "Compression"},
            {"140000-149999", "System Recovery"},
            {"40000-49999", "FSFilter Bottom"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/minifilter/check_altitude_ordering", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["altitude_threat_analysis"] = {
            "A malicious minifilter registered with altitude > 330,000 intercepts and hides file I/O BEFORE Anti-Virus filters see the request",
            "A malicious minifilter with altitude < 320,000 can tamper with file data on disk after Anti-Virus has already validated the pre-operation buffer",
            "Verification requires checking registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\[Driver]\\Instances"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/minifilter/validate_callback_pointers", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["validation_rules"] = "All FLT_OPERATION_REGISTRATION callback pointers must reside within signed kernel driver modules listed in PsLoadedModuleList";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
