#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_kpcr_kprcb_routes(c_http_router& router) {
    router.post("/api/kpcr/dump_all_cpus", [](const httplib::Request&, httplib::Response& res) {
        json result;
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        result["logical_processor_count"] = si.dwNumberOfProcessors;
        result["architecture"] = si.wProcessorArchitecture;
        
        result["kpcr_offsets_x64"] = {
            {"NtTib", "NT_TIB self-referencing descriptor at GS:0x00"},
            {"GdtBase", "GDT Base Address pointer at GS:0x38"},
            {"TssBase", "Task State Segment Base at GS:0x40"},
            {"UserRsp", "User-mode RSP stash during SYSCALL entry at GS:0x48"},
            {"Self", "Pointer to KPCR self at GS:0x50"},
            {"CurrentPrcb", "Pointer to embedded KPRCB at GS:0x180"},
            {"IdtBase", "IDT Base Address pointer at GS:0x038 in modern builds / IDTR stashed"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/kpcr/read_prcb_fields", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["kprcb_structure"] = {
            {"CurrentThread", "_KTHREAD* currently executing on this core (offset 0x008)"},
            {"NextThread", "_KTHREAD* selected by scheduler for next quantum"},
            {"IdleThread", "_KTHREAD* idle thread routine"},
            {"DpcData", "KDPC_DATA array for Normal and Threaded DPCs"},
            {"DpcRoutineActive", "Boolean flag set during DPC queue servicing"},
            {"KeSystemCalls", "Cumulative counter of SYSCALL/SYSENTER instructions on core"},
            {"HalReserved", "HAL private scratch region used for timer and IPI dispatch"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/kpcr/detect_dpc_anomalies", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["dpc_hijacking_techniques"] = {
            {"KDPC_DeferredRoutine_Hook", "Overwriting DeferredRoutine pointer in pre-allocated timer DPC to gain kernel execution"},
            {"DpcQueue_Unlinking", "Inserting unlinked DPC objects directly into PRCB DpcList to evade kernel telemetry"},
            {"Timer_DPC_Tampering", "Modifying KTIMER.Dpc target routine for asynchronous kernel execution"}
        };
        result["detection_strategy"] = "Enumerate registered KDPC objects and cross-check target routine addresses against loaded kernel driver range";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
