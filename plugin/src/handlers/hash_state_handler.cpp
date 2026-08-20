#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hash_state_routes(c_http_router& router) {
    // GET /api/hash_state/scan
    router.get("/api/hash_state/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hash_contexts_found", 0},
            {"candidates", nlohmann::json::array()}
        });
    });

    // POST /api/hash_state/sha256
    router.post("/api/hash_state/sha256", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"h0", "0x6A09E667"}, {"h1", "0xBB67AE85"}, {"h2", "0x3C6EF372"}, {"h3", "0xA54FF53A"},
            {"h4", "0x510E527F"}, {"h5", "0x9B05688C"}, {"h6", "0x1F83D9AB"}, {"h7", "0x5BE0CD19"}
        });
    });

    // POST /api/hash_state/sha512
    router.post("/api/hash_state/sha512", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"h0", "0x6A09E667F3BCC908"}, {"h1", "0xBB67AE8584CAA73B"}
        });
    });

    // POST /api/hash_state/md5
    router.post("/api/hash_state/md5", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"a", "0x67452301"}, {"b", "0xEFCDAB89"}, {"c", "0x98BADCFE"}, {"d", "0x10325476"}
        });
    });
}

} // namespace handlers
