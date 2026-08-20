#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_mem_artifact_correlator_routes(c_http_router& router) {
    router.post("/api/mem_correlate/scan_ioc_patterns", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["ioc_categories"] = {
            {"IPv4_Addresses", "Regular expression matching valid public IPv4 address sequences in heap/stack"},
            {"URLs_Domains", "http://, https://, tcp://, ws://, wss:// URL strings and FQDN candidates"},
            {"Crypto_Keys", "PEM headers ('-----BEGIN RSA PRIVATE KEY-----'), raw 32-byte AES keys, ECC curves"},
            {"Wallet_Addresses", "Bitcoin (1, 3, bc1), Ethereum (0x), Monero (4, 8) cryptocurrency wallet regexes"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/mem_correlate/find_embedded_pes", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["embedded_pe_detection"] = {
            "1. Scan heap, private memory, and stack for DOS header signature (0x5A4D 'MZ')",
            "2. Read e_lfanew offset (offset 0x3C) -> verify NT Headers signature (0x00004550 'PE\\0\\0')",
            "3. Verify FileHeader.Machine (0x8664 = x64, 0x014C = x86) and OptionalHeader.Magic",
            "4. Distinguish between properly mapped PE images vs unmapped / raw staged payload buffers"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/mem_correlate/extract_network_iocs", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["network_ioc_correlation"] = "Correlates discovered string artifacts with active socket table entries to score high-confidence C2 infrastructure";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
