#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_uaf_detector_routes(c_http_router& router) {
    router.post("/api/uaf/tag_allocations", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["heap_tagging_concept"] = {
            "1. Intercept HeapAlloc / RtlAllocateHeap and embed 8-byte canary tag at chunk header",
            "2. Intercept HeapFree / RtlFreeHeap and overwrite chunk payload with poison pattern (0xDEADBEEF / 0xCC)",
            "3. Retain chunk in quarantined delay-free list to prevent immediate reallocation",
            "4. Trap any subsequent read/write access to freed memory page using PAGE_GUARD or hardware watchpoints"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/uaf/detect_stale_access", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["uaf_exploitation_phases"] = {
            {"Dangling_Pointer_Creation", "Object freed without clearing referencing pointer in calling component"},
            {"Heap_Feng_Shui_Grooming", "Spraying fake object into freed chunk memory slot with controlled vtable pointer"},
            {"Virtual_Method_Invocation", "Dangling pointer calls virtual function -> redirects RIP to attacker gadget"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/uaf/analyze_heap_entropy", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["heap_aslr_assessment"] = "Evaluates LFH (Low Fragmentation Heap) randomization entropy to calculate exploit predictability for user-after-free chunk replacement";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
