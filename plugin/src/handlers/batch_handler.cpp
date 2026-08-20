#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"

#include <chrono>
#include <nlohmann/json.hpp>
#include "bridgemain.h"

namespace handlers {

void register_batch_routes(c_http_router& router) {
    router.post("/api/batch", [&router](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("requests") || !body["requests"].is_array()) {
            return s_http_response::bad_request("Missing 'requests' array");
        }

        int max_concurrency = body.value("max_concurrency", 1);
        if (max_concurrency < 1) max_concurrency = 1;

        auto start_time = std::chrono::steady_clock::now();
        auto results = nlohmann::json::array();
        const auto& requests = body["requests"];

        for (const auto& req_item : requests) {
            if (!req_item.contains("method") || !req_item.contains("path")) {
                results.push_back({
                    {"status", 400},
                    {"error", "Missing 'method' and/or 'path' fields in request item"}
                });
                continue;
            }

            std::string method = req_item["method"].get<std::string>();
            std::string path = req_item["path"].get<std::string>();
            std::unordered_map<std::string, std::string> query_map;
            std::string body_str;

            if (req_item.contains("query") && req_item["query"].is_object()) {
                for (auto& [key, val] : req_item["query"].items()) {
                    if (val.is_string()) {
                        query_map[key] = val.get<std::string>();
                    } else {
                        query_map[key] = val.dump();
                    }
                }
            }

            if (req_item.contains("body")) {
                if (req_item["body"].is_string()) {
                    body_str = req_item["body"].get<std::string>();
                } else {
                    body_str = req_item["body"].dump();
                }
            }

            s_http_request sub_req;
            sub_req.method = method;
            sub_req.path = path;
            sub_req.query = std::move(query_map);
            sub_req.body = std::move(body_str);

            try {
                auto resp = router.dispatch(sub_req);
                nlohmann::json result;
                result["status"] = resp.status_code;

                try {
                    auto parsed = nlohmann::json::parse(resp.body);
                    if (resp.status_code >= 200 && resp.status_code < 300) {
                        if (parsed.contains("data")) {
                            result["data"] = parsed["data"];
                        } else {
                            result["data"] = parsed;
                        }
                    } else {
                        if (parsed.contains("error")) {
                            result["error"] = parsed["error"];
                        } else {
                            result["error"] = resp.body;
                        }
                    }
                } catch (...) {
                    if (resp.status_code >= 200 && resp.status_code < 300) {
                        result["data"] = resp.body;
                    } else {
                        result["error"] = resp.body;
                    }
                }
                results.push_back(std::move(result));
            } catch (const std::exception& e) {
                results.push_back({
                    {"status", 500},
                    {"error", std::string("Handler exception: ") + e.what()}
                });
            } catch (...) {
                results.push_back({
                    {"status", 500},
                    {"error", "Unknown handler exception"}
                });
            }
        }

        auto end_time = std::chrono::steady_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        return s_http_response::ok({
            {"results", results},
            {"count", results.size()},
            {"duration_ms", duration_ms}
        });
    });
}

} // namespace handlers
