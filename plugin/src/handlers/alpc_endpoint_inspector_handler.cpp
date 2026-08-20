#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_alpc_endpoint_inspector_routes(c_http_router& router) {
    router.post("/api/alpc_endpoint/enumerate_ports", [](const s_http_request& req) {
        json result;
        result["well_known_alpc_ports"] = {
            {"\\RPC Control\\epmapper", "RPC Endpoint Mapper"},
            {"\\RPC Control\\LSA_AUTHENTICATION_INITIALIZED", "Local Security Authority authentication port"},
            {"\\RPC Control\\ScmReplyPort", "Service Control Manager notification port"},
            {"\\RPC Control\\AppxAllUserStore", "AppX package deployment manager port"},
            {"\\Windows\\ThemePort", "Windows Theme service ALPC connection"}
        };
        result["alpc_message_attributes"] = {
            {"ALPC_MESSAGE_SECURITY_ATTRIBUTE", "Client token impersonation level and context tracking"},
            {"ALPC_MESSAGE_VIEW_ATTRIBUTE", "Shared Section View mapping for high-throughput zero-copy data transfer"},
            {"ALPC_MESSAGE_HANDLE_ATTRIBUTE", "Direct kernel object handle passing across IPC boundaries"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/alpc_endpoint/decode_message_headers", [](const s_http_request& req) {
        json result;
        result["port_message_layout"] = {
            {"DataLength", "16-bit payload length following PORT_MESSAGE header"},
            {"TotalLength", "16-bit total message size (Header 0x28 bytes + DataLength)"},
            {"Type", "LPC_REQUEST (1), LPC_REPLY (2), LPC_DATAGRAM (3), LPC_LOST_REPLY (4), LPC_PORT_CLOSED (5)"},
            {"DataInfoOffset", "Offset to ALPC message attributes structure"},
            {"ClientId", "CLIENT_ID { UniqueProcess, UniqueThread }"},
            {"MessageId", "Monotonically increasing message transaction ID"},
            {"CallbackId", "Asynchronous callback tracking ID"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

