#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_load_config_deep_routes(c_http_router& router) {
    router.post("/api/load_config/parse_security_mitigations", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["load_config_mitigations_directory"] = {
            {"GuardCFCheckFunctionPointer", "RVA of ntdll!LdrpValidateUserCallTarget / CFG bitmap lookup function"},
            {"GuardCFDispatchFunctionPointer", "RVA of ntdll!LdrpDispatchUserCallTarget function"},
            {"GuardCFFunctionTable", "Pointer to sorted table of valid indirect call target RVAs"},
            {"GuardCFFunctionCount", "Number of valid indirect call targets in table"},
            {"GuardFlags", "0x00000100 = CF_INSTRUMENTED, 0x00000400 = CF_FUNCTION_TABLE_PRESENT, 0x00004000 = EXPORT_SUPPRESSION_INFO_PRESENT"},
            {"GuardAddressTakenIatTable", "Table of IAT entries whose addresses are taken"},
            {"GuardLongJmpTargetTable", "Valid targets for setjmp/longjmp across stack frames"},
            {"CastGuardOsDeterminedFailureMode", "CastGuard C++ polymorphic downcast validation table"},
            {"GuardEHContinuationTable", "Valid exception handler continuation targets (CET / Shadow Stack protection)"},
            {"GuardEHContinuationCount", "Count of EH continuation addresses"},
            {"GuardXFGCheckFunctionPointer", "Extended Flow Guard (XFG) type hash validation check pointer"},
            {"GuardXFGDispatchFunctionPointer", "Extended Flow Guard (XFG) dispatch pointer"},
            {"GuardXFGTableDispatchFunctionPointer", "XFG table dispatch pointer"},
            {"CastGuardOsDeterminedFailureMode", "Type confusion exploit prevention table"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/load_config/audit_cet_shadow_stack", [](const s_http_request& req) {
        json result;
        result["cet_shadow_stack_mechanisms"] = {
            {"Hardware_Enforcement", "Intel CET / AMD Shadow Stack maintains dedicated hardware shadow stack page pool"},
            {"INCSSP_WRSS", "INCSSP (Increment Shadow Stack Pointer) and WRSS (Write to Shadow Stack) privileged instructions"},
            {"GuardEHContinuationTable", "Required to prevent CET #CP (Control Protection Exception) during SEH __except unwinding"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

