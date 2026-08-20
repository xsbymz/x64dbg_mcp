#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_raw_socket_routes(c_http_router& router) {
    router.post("/api/raw_socket/enumerate_raw_sockets", [](const s_http_request& req) {
        json result;
        result["raw_socket_api"] = "WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW / IPPROTO_ICMP / IPPROTO_IP)";
        result["requirements"] = "Requires Administrator / SeDebugPrivilege / elevated security token";
        result["c2_tunneling_applications"] = {
            {"ICMP_Tunneling", "Encapsulates TCP/UDP payloads inside ICMP Echo Request/Reply data payloads (PingTunnel, PTunnel, icmpsh)"},
            {"GRE_Tunneling", "Generic Routing Encapsulation (IP protocol 47) for stealth multi-hop routing"},
            {"Custom_IP_Protocols", "Arbitrary protocol numbers in IPv4 header to bypass port-based network firewalls"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/raw_socket/detect_icmp_tunneling_patterns", [](const s_http_request& req) {
        json result;
        result["icmp_tunnel_heuristics"] = {
            "1. ICMP Echo payload size > 64 bytes (standard ping is 32 or 64 bytes)",
            "2. High frequency of ICMP traffic to non-gateway external IP addresses",
            "3. High Shannon entropy in ICMP payload data indicating encryption or compression",
            "4. Process opening socket handle with SOCK_RAW and IPPROTO_ICMP"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/raw_socket/correlate_with_network_activity", [](const s_http_request& req) {
        json result;
        result["audit_approach"] = {
            "Correlate handle table entries of type '\\Device\\Afd' with WSK / Winsock API calls in process trace",
            "Verify process token membership in Administrators / Network Configuration Operators"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

