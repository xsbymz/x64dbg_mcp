#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_gargoyle_sleep_routes(c_http_router& router) {
    router.post("/api/gargoyle/scan_waitable_timers", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["gargoyle_timer_mechanism"] = {
            "1. Uses CreateWaitableTimerW / SetWaitableTimer or NtSetTimer2",
            "2. Completion routine points to ROP pivot gadget or NtContinue",
            "3. ROP gadget chain executes VirtualProtect (PAGE_READWRITE -> PAGE_EXECUTE_READWRITE)",
            "4. Decrypts shellcode body in memory, executes quantum, re-encrypts, flips back to PAGE_READONLY/PAGE_NOACCESS",
            "5. Sets next waitable timer before going dormant"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/gargoyle/detect_rop_apc_chains", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["sleep_obfuscation_frameworks"] = {
            {"Gargoyle", "Pioneered ROP-based timer APC memory permission toggling"},
            {"Ekko", "Uses RtlCreateTimer + CreateEvent with CONTEXT manipulation via NtContinue"},
            {"Foliage", "Uses TpAllocTimer + NtQueueApcThread for stealth thread pool sleep encryption"},
            {"Cronos", "Employs WaitOnAddress + SRWLock timeout callbacks to avoid timer object handles"}
        };
        result["signature_patterns"] = {
            "Presence of SystemFunction032 / SystemFunction033 (RC4 memory encryption) in import/call stack",
            "Repeated VirtualProtect / NtProtectVirtualMemory transitions between RX and RW on non-image memory",
            "Stack pointer outside legitimate thread stack bounds during APC dispatch"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/gargoyle/find_non_executable_suspicious_regions", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["detection_heuristic"] = "Identify private committed MEM_READWRITE / PAGE_NOACCESS regions containing PE header signatures (MZ/PE) or high-entropy encrypted blobs that were previously observed with execution rights";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
