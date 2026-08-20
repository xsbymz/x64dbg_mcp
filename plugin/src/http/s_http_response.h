#pragma once

#include <string>
#include <sstream>
#include <nlohmann/json.hpp>

struct s_http_response {
    int status_code = 200;
    std::string content_type = "application/json";
    std::string body;

    static constexpr size_t MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50MB

    // Build a success response with data payload
    static s_http_response ok(const nlohmann::json& data) {
        nlohmann::json envelope = {
            {"success", true},
            {"data", data}
        };
        return {200, "application/json", envelope.dump()};
    }

    // Build an error response
    static s_http_response error(int code, const std::string& message) {
        nlohmann::json envelope = {
            {"success", false},
            {"error", {
                {"code", code},
                {"message", message}
            }}
        };
        return {code, "application/json", envelope.dump()};
    }

    // 400 Bad Request
    static s_http_response bad_request(const std::string& message) {
        return error(400, message);
    }

    // 401 Unauthorized (missing/invalid auth token)
    static s_http_response unauthorized(const std::string& message = "Unauthorized") {
        return error(401, message);
    }

    // 404 Not Found
    static s_http_response not_found(const std::string& message = "Not found") {
        return error(404, message);
    }

    // 409 Conflict (wrong debugger state)
    static s_http_response conflict(const std::string& message) {
        return error(409, message);
    }

    // 500 Internal Server Error
    static s_http_response internal_error(const std::string& message) {
        return error(500, message);
    }

    // 429 Too Many Requests
    static s_http_response rate_limited(const std::string& message = "Too Many Requests") {
        return error(429, message);
    }

    // 413 Payload Too Large
    static s_http_response payload_too_large(const std::string& message = "Payload Too Large") {
        return error(413, message);
    }

    // Serialize to HTTP response string
    [[nodiscard]] std::string serialize() const {
        std::string body_copy = body;
        if (body_copy.size() > MAX_RESPONSE_SIZE) {
            std::string truncated = body_copy.substr(0, MAX_RESPONSE_SIZE);
            try {
                auto j = nlohmann::json::parse(truncated);
                j["warning"] = "Response truncated to 50MB limit";
                j["truncated"] = true;
                body_copy = j.dump();
            } catch (...) {
                nlohmann::json fallback = {
                    {"warning", "Response truncated to 50MB limit"},
                    {"truncated", true},
                    {"data", truncated}
                };
                body_copy = fallback.dump();
            }
        }

        std::ostringstream oss;
        oss << "HTTP/1.1 " << status_code << " " << status_text() << "\r\n";
        oss << "Content-Type: " << content_type << "\r\n";
        oss << "Content-Length: " << body_copy.size() << "\r\n";
        oss << "Connection: close\r\n";
        // No permissive CORS: this is a localhost-only API consumed by the Node
        // MCP server (which is not subject to CORS). Emitting "Allow-Origin: *"
        // would let any web page in a local browser drive the debugger, so we
        // deliberately send no Access-Control-Allow-* headers.
        oss << "\r\n";
        oss << body_copy;
        return oss.str();
    }

private:
    [[nodiscard]] std::string status_text() const {
        switch (status_code) {
            case 200: return "OK";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 409: return "Conflict";
            case 413: return "Payload Too Large";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            default:  return "Unknown";
        }
    }
};
