#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_protobuf_decoder_routes(c_http_router& router) {
    router.post("/api/protobuf/scan_memory", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["protobuf_wire_format"] = {
            {"Varint (0)", "int32, int64, uint32, uint64, sint32, sint64, bool, enum"},
            {"64-bit (1)", "fixed64, sfixed64, double"},
            {"Length-delimited (2)", "string, bytes, embedded messages, packed repeated fields"},
            {"Start_Group (3)", "Deprecated grouping delimiter"},
            {"End_Group (4)", "Deprecated grouping delimiter"},
            {"32-bit (5)", "fixed32, sfixed32, float"}
        };
        result["tag_encoding"] = "(field_number << 3) | wire_type";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/protobuf/decode_wire_format", [](const s_http_request& req) {
        json result;
        result["decoding_algorithm"] = {
            "1. Read Varint tag byte -> extract wire_type and field_number",
            "2. If wire_type == 0: parse variable length Varint value using MSB continuation bit",
            "3. If wire_type == 1: read next 8 bytes as little-endian 64-bit integer / double",
            "4. If wire_type == 2: read Varint length L, then consume next L bytes (string or sub-message)",
            "5. If wire_type == 5: read next 4 bytes as little-endian 32-bit integer / float",
            "6. Recursively decompress nested message structures"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/protobuf/detect_grpc_c2", [](const s_http_request& req) {
        json result;
        result["grpc_c2_threats"] = {
            "Modern C2 frameworks (Sliver, Havoc, Mythic) encapsulate gRPC protocol buffers over HTTP/2",
            "gRPC frame structure: 1-byte compression flag + 4-byte message length + Protobuf binary payload",
            "Signatures: 'application/grpc', 'application/grpc+proto', 'grpc-status', 'grpc-message' in HTTP headers"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

