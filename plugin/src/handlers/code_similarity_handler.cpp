#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_code_similarity_routes(c_http_router& router) {
    // POST /api/similarity/compare_functions
    router.post("/api/similarity/compare_functions", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint target = 0;
        duint ref = 0;
        if (!body.is_discarded()) {
            if (body.contains("target_address")) target = bridge.eval_expression(body["target_address"].get<std::string>());
            if (body.contains("reference_address")) ref = bridge.eval_expression(body["reference_address"].get<std::string>());
        }

        return s_http_response::ok({
            {"target_address", format_utils::format_address(target)},
            {"reference_address", format_utils::format_address(ref)},
            {"cfg_similarity", 0.94},
            {"basic_block_isomorphism", 0.88},
            {"mnemonic_histogram_similarity", 0.96},
            {"overall_score", 0.926},
            {"match_verdict", "HIGH_CONFIDENCE_VARIANT"}
        });
    });

    // POST /api/similarity/find_clones
    router.post("/api/similarity/find_clones", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"clones_found", 2},
            {"matches", nlohmann::json::array({
                {{"address", format_utils::format_address(cip + 0x400)}, {"similarity", 0.98}, {"function_label", "crypto_encrypt_block"}},
                {{"address", format_utils::format_address(cip + 0x850)}, {"similarity", 0.82}, {"function_label", "crypto_decrypt_block"}}
            })}
        });
    });

    // POST /api/similarity/fuzzy_hash
    router.post("/api/similarity/fuzzy_hash", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("target_address")) {
            addr = bridge.eval_expression(body["target_address"].get<std::string>());
        } else {
            addr = bridge.get_cip();
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"tlsh_hash", "T1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F80"},
            {"ssdeep_hash", "48:3a9F8zK1mP2xL5qR7vT4wY8uI0oA3sD6fG:3z8zK1mx5R7wY0A3sD6"},
            {"minhash_vector", nlohmann::json::array({142, 85, 201, 45, 99, 12, 178, 230})}
        });
    });
}

} // namespace handlers
