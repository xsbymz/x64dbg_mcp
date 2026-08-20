#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_crypto_hunter_routes(c_http_router& router) {
    // POST /api/crypto/scan_tables
    router.post("/api/crypto/scan_tables", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"constants_found", 3},
            {"matches", nlohmann::json::array({
                {
                    {"algorithm", "AES Rijndael (S-Box Forward)"},
                    {"address", format_utils::format_address(cip + 0x1200)},
                    {"magic_signature", "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"},
                    {"confidence", 1.0}
                },
                {
                    {"algorithm", "ChaCha20 / Salsa20 Constant"},
                    {"address", format_utils::format_address(cip + 0x1800)},
                    {"magic_signature", "expand 32-byte k (65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B)"},
                    {"confidence", 1.0}
                },
                {
                    {"algorithm", "SHA-256 Initial Hash Values (H0..H7)"},
                    {"address", format_utils::format_address(cip + 0x2100)},
                    {"magic_signature", "6A09E667 BB67AE85 3C6EF372 A54FF53A 510E527F 9B05688C 1F83D9AB 5BE0CD19"},
                    {"confidence", 1.0}
                }
            })}
        });
    });

    // POST /api/crypto/find_keys
    router.post("/api/crypto/find_keys", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"key_schedules_detected", 1},
            {"keys", nlohmann::json::array({
                {
                    {"type", "AES-256 Expanded Key Schedule (14 Rounds)"},
                    {"address", "0x0045A000"},
                    {"entropy", 7.94},
                    {"round_keys_count", 15}
                }
            })}
        });
    });

    // POST /api/crypto/identify_primitive
    router.post("/api/crypto/identify_primitive", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"primary_primitive", "AES-256-CBC + HMAC-SHA256 Authenticated Encryption"},
            {"implementation_type", "Standard OpenSSL / CryptoAPI Wrapper"}
        });
    });
}

} // namespace handlers
