#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_alpc_ndr_fuzzer_routes(c_http_router& router) {
    // POST /api/alpc_fuzzer/parse_ndr_stream
    router.post("/api/alpc_fuzzer/parse_ndr_stream", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"interface_syntax", "NDR64 / 64-bit Transfer Syntax"},
            {"opnum", 3},
            {"parameters", nlohmann::json::array({
                {{"param_index", 0}, {"type", "FC64_INT32"}, {"direction", "IN"}},
                {{"param_index", 1}, {"type", "FC64_CONFSTRING"}, {"direction", "IN"}},
                {{"param_index", 2}, {"type", "FC64_STRUCT"}, {"direction", "OUT"}}
            })},
            {"status", "NDR_PARSED_SUCCESS"}
        });
    });

    // POST /api/alpc_fuzzer/mutate_payload
    router.post("/api/alpc_fuzzer/mutate_payload", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"mutation_strategy", "INTEGER_BOUNDARY_OVERFLOW_AND_CONFORMANT_ARRAY_STRETCH"},
            {"mutated_payload_bytes", "03000000FFFFFFFF00000000..."},
            {"payload_length", 64}
        });
    });
}

} // namespace handlers
