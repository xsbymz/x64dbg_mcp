#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_eh_rop_gadget_routes(c_http_router& router) {
    router.post("/api/eh_rop/enumerate_handler_addresses", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["exception_directory_structures"] = {
            {"RUNTIME_FUNCTION", "BeginAddress, EndAddress, UnwindInfoAddress in .pdata section"},
            {"UNWIND_INFO", "Version, Flags (UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER), SizeOfProlog, CountOfCodes"},
            {"ExceptionHandler", "Function pointer to __C_specific_handler, __CxxFrameHandler3/4, or custom filter"},
            {"ScopeTable", "Array of { BeginAddress, EndAddress, HandlerAddress, TargetAddress } defining __try/__except blocks"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/eh_rop/extract_gadgets_from_handlers", [](const s_http_request& req) {
        json result;
        result["gadget_quality_factors"] = {
            {"CFG_Valid_Target", "Exception handlers are marked as valid indirect call targets in CFG bitmaps"},
            {"Unwind_Epilogues", "Exception filter and finally routines contain clean register restoration and RET instructions"},
            {"Non_Volatile_Registers", "Handlers frequently load RBX, RDI, RSI, R12-R15 before unwinding, providing excellent ROP register setters"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/eh_rop/build_authenticated_gadget_set", [](const s_http_request& req) {
        json result;
        result["authenticated_rop_advantage"] = "Gadgets sourced from legitimate exception handlers pass CFG verification and runtime call target validation, making them highly resilient against modern exploit mitigations";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

