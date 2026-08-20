#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_cfi_analyzer_routes(c_http_router& router) {
    router.post("/api/cfi/dump_cfg_bitmap", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["control_flow_guard_architecture"] = {
            {"GuardCFCheckFunctionPointer", "Points to ntdll!LdrpValidateUserCallTarget / CFG check routine"},
            {"GuardCFDispatchFunctionPointer", "Points to ntdll!LdrpDispatchUserCallTarget for tail calls"},
            {"CFG_Bitmap", "System-wide bitmap where 2 bits represent every 16 bytes of address space (00=invalid, 01=suppressed, 10=export suppressed, 11=valid target)"},
            {"GuardCFFunctionTable", "Array of RVAs in LoadConfig directory marking valid indirect call targets"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/cfi/find_cfg_bypass_gadgets", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["cfg_bypass_techniques"] = {
            {"Valid_Target_Abuse", "Calling valid CFG targets in unexpected order (e.g. SetProcessValidCallTargets, VirtualProtect, NtContinue)"},
            {"Non_CFG_Modules", "Indirect calls dispatched to legacy modules loaded without /guard:cf compiler flag"},
            {"Return_Address_Overwrite", "CFG only protects forward-edge indirect calls (CALL RAX), NOT backward-edge return addresses (requires Intel CET shadow stack)"},
            {"JIT_Code_Gaps", "JIT-compiled memory pages lacking granular CFG bitmap registration"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/cfi/analyze_valid_call_targets", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["analysis_workflow"] = "Parse IMAGE_LOAD_CONFIG_DIRECTORY -> GuardCFFunctionTable to enumerate all valid indirect call target RVAs and identify functions with sensitive parameter conventions (e.g. memory manipulation or process spawning)";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
