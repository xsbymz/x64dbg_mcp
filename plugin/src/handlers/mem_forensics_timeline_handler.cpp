#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_mem_forensics_timeline_routes(c_http_router& router) {
    router.post("/api/mem_timeline/reconstruct_allocation_order", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["reconstruction_sources"] = {
            {"ETW_Memory_Provider", "Microsoft-Windows-Kernel-Memory (Allocation timestamps and stack traces)"},
            {"Virtual_Page_Number_Order", "Sequential analysis of committed memory regions"},
            {"Heap_Segment_Timestamps", "Creation timestamps in HEAP_SEGMENT structures"},
            {"Thread_Stack_Allocations", "TEB.StackBase allocations correlated with thread creation times"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/mem_timeline/correlate_with_thread_creation", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["injection_timeline_patterns"] = {
            "VirtualAlloc(MEM_COMMIT, PAGE_READWRITE) -> WriteProcessMemory -> VirtualProtect(PAGE_EXECUTE_READ) -> CreateRemoteThread",
            "Process Hollowing: NtUnmapViewOfSection -> VirtualAlloc -> WriteProcessMemory -> SetThreadContext -> ResumeThread",
            "Early Bird APC: CreateProcess(CREATE_SUSPENDED) -> VirtualAllocEx -> WriteProcessMemory -> QueueUserApc -> ResumeThread"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/mem_timeline/export_forensic_sequence", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["export_format"] = "Chronological JSON event sequence with UTC microsecond timestamps for incident response timeline graphing";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
