#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_http2_frame_routes(c_http_router& router) {
    router.post("/api/http2/scan_memory_for_frames", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["http2_client_preface"] = "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n (0x505249202a20485454502f322e30...)";
        result["frame_header_format"] = {
            {"Length", "24-bit unsigned integer (bytes 0-2)"},
            {"Type", "8-bit frame type identifier (byte 3)"},
            {"Flags", "8-bit type-specific boolean flags (byte 4)"},
            {"Reserved_StreamID", "1-bit reserved + 31-bit stream identifier (bytes 5-8)"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/http2/decode_frame_stream", [](const s_http_request& req) {
        json result;
        result["http2_frame_types"] = {
            {"0x00", "DATA — Carries application payload data"},
            {"0x01", "HEADERS — Contains HPACK-compressed HTTP headers"},
            {"0x02", "PRIORITY — Stream sender priority hints"},
            {"0x03", "RST_STREAM — Immediate stream termination"},
            {"0x04", "SETTINGS — Connection configuration parameters"},
            {"0x05", "PUSH_PROMISE — Server push advertisement"},
            {"0x06", "PING — Round-trip latency and keepalive frame"},
            {"0x07", "GOAWAY — Connection shutdown initiation"},
            {"0x08", "WINDOW_UPDATE — Flow control credit advertisement"},
            {"0x09", "CONTINUATION — Extends HEADERS frame payload"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/http2/extract_c2_indicators", [](const s_http_request& req) {
        json result;
        result["advanced_c2_usage"] = {
            "Brute Ratel C4 / Nighthawk C2 utilize HTTP/2 multiplexed streams for concurrent tasking and file transfer",
            "HPACK dynamic table exploitation to hide C2 headers across multiple requests",
            "SETTINGS frame timing manipulation as steganographic signaling channel"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

