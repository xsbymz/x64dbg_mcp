#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_ndr_format_decoder_routes(c_http_router& router) {
    router.post("/api/ndr_format/decode_type_format_string", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string hexFormat = body.value("format_string_hex", "");
        json result;
        result["format_string_hex"] = hexFormat;
        result["ndr_type_tokens"] = {
            {"0x01", "FC_BYTE — 8-bit unsigned integer"},
            {"0x02", "FC_CHAR — 8-bit character"},
            {"0x03", "FC_SMALL — 8-bit signed integer"},
            {"0x04", "FC_USMALL — 8-bit unsigned integer"},
            {"0x05", "FC_WCHAR — 16-bit Unicode character"},
            {"0x06", "FC_SHORT — 16-bit signed integer"},
            {"0x07", "FC_USHORT — 16-bit unsigned integer"},
            {"0x08", "FC_LONG — 32-bit signed integer"},
            {"0x09", "FC_ULONG — 32-bit unsigned integer"},
            {"0x0A", "FC_FLOAT — 32-bit IEEE float"},
            {"0x0B", "FC_HYPER — 64-bit integer"},
            {"0x0C", "FC_DOUBLE — 64-bit double"},
            {"0x11", "FC_RP — Reference Pointer (Cannot be NULL)"},
            {"0x12", "FC_UP — Unique Pointer (Can be NULL)"},
            {"0x13", "FC_OP — Object Pointer (Interface pointer / IUnknown)"},
            {"0x14", "FC_FP — Full Pointer (Supports aliasing graph)"},
            {"0x15", "FC_STRUCT — Simple structure"},
            {"0x16", "FC_PSTRUCT — Pointer-containing structure"},
            {"0x17", "FC_CSTRUCT — Conformant array structure"},
            {"0x18", "FC_CPSTRUCT — Conformant pointer structure"},
            {"0x1B", "FC_CARRAY — Conformant 1D array"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/ndr_format/parse_rpc_proc_format", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["ndr_proc_format_header"] = {
            {"HandleType", "Explicit (FC_BIND_PRIMITIVE, FC_BIND_GENERIC, FC_BIND_CONTEXT) vs Implicit"},
            {"OiFlags", "Interpreter optimization flags (Oi, Oic, Oif, Oicf)"},
            {"RpcFlags", "RPC_FLAGS_IDEMPOTENT, RPC_FLAGS_ASYNC"},
            {"ProcNum", "Method ordinal index in interface vtable"},
            {"StackSize", "Total parameter size in bytes pushed to stack on x86/x64"},
            {"ExplicitHandleOffset", "Offset to binding handle parameter"},
            {"ClientCorrHint", "Correlation hint byte count for complex arrays"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
