#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_doh_detector_routes(c_http_router& router) {
    router.post("/api/doh/detect_active_connections", [](const s_http_request& req) {
        json result;
        result["known_public_doh_resolvers"] = {
            {"Cloudflare", "1.1.1.1:443 / 1.0.0.1:443 (cloudflare-dns.com)"},
            {"Google", "8.8.8.8:443 / 8.8.4.4:443 (dns.google)"},
            {"Quad9", "9.9.9.9:443 / 149.112.112.112:443 (dns.quad9.net)"},
            {"OpenDNS", "208.67.222.222:443 / 208.67.220.220:443"},
            {"AdGuard", "94.140.14.14:443 / 94.140.15.15:443"}
        };
        result["detection_method"] = "Query TCP table for active socket connections to known DoH IPs on port 443 originating from non-browser and non-system binaries";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/doh/scan_memory_for_doh_ips", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["search_strings"] = {
            "https://1.1.1.1/dns-query",
            "https://dns.google/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "application/dns-message",
            "application/dns-json"
        };
        result["threat_rationale"] = "Malware embeds direct DoH URLs to bypass enterprise DNS sinkholes, inspection proxies, and DNS query logging";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/doh/correlate_resolver_bypasses", [](const s_http_request& req) {
        json result;
        result["evasion_techniques"] = {
            {"Hardcoded_DoH", "Application executes HTTPS requests to DoH endpoint without calling DnsQuery_W / getaddrinfo"},
            {"DNS_Over_TLS", "Direct TCP 853 connections"},
            {"Hosts_File_Bypass", "Direct IP resolution with SNI header manipulation"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

