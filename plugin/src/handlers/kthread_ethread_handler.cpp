#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <tlhelp32.h>
using json = nlohmann::json;

namespace handlers {
void register_kthread_ethread_routes(c_http_router& router) {
    router.post("/api/kthread/walk_all_threads", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["threads"] = json::array();

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == targetPid) {
                        json tinfo;
                        tinfo["tid"] = te.th32ThreadID;
                        tinfo["base_priority"] = te.tpBasePri;
                        
                        HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                        if (hThread) {
                            FILETIME ct{}, et{}, kt{}, ut{};
                            if (GetThreadTimes(hThread, &ct, &et, &kt, &ut)) {
                                tinfo["kernel_time_raw"] = ((uint64_t)kt.dwHighDateTime << 32) | kt.dwLowDateTime;
                                tinfo["user_time_raw"] = ((uint64_t)ut.dwHighDateTime << 32) | ut.dwLowDateTime;
                            }
                            CloseHandle(hThread);
                        }
                        result["threads"].push_back(tinfo);
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }

        result["kthread_fields_reference"] = {
            {"Header", "_DISPATCHER_HEADER at offset 0x00"},
            {"ApcState", "KAPC_STATE at offset 0x98 (ApcListHead[2], Process, KernelApcPending)"},
            {"InitialStack", "Initial kernel stack pointer (StackBase)"},
            {"StackLimit", "Lower limit of kernel stack allocation (4KB or 24KB in modern x64)"},
            {"TrapFrame", "Saved context during user/kernel transition (offset 0x090 on x64)"},
            {"Win32Thread", "Pointer to win32kthread desktop GUI state"},
            {"WaitBlockList", "Array of KWAIT_BLOCK structures indicating synchronization objects waited on"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/kthread/dump_thread_fields", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD tid = body.value("tid", (DWORD)GetCurrentThreadId());
        json result;
        result["tid"] = tid;
        result["ethread_architecture"] = {
            {"Tcb", "Embedded _KTHREAD at offset 0x00"},
            {"CreateTime", "LARGE_INTEGER thread spawn timestamp"},
            {"ExitTime", "LARGE_INTEGER thread termination timestamp"},
            {"ExitStatus", "NTSTATUS return code upon exit"},
            {"PostBlockList", "LIST_ENTRY for LPC/ALPC reply queuing"},
            {"Cid", "CLIENT_ID { UniqueProcess, UniqueThread }"},
            {"KeyedWaitSemaphore", "Fast user-mode synchronization semaphore"},
            {"AlpcMessageId", "Active ALPC communication message tracker"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/kthread/detect_apc_anomalies", [](const s_http_request& req) {
        json result;
        result["apc_anomaly_heuristics"] = {
            "1. KernelApcPending=1 with empty ApcListHead indicates unlinked/stealth APC execution",
            "2. ApcStateIndex pointing to foreign process while thread is executing kernel routine",
            "3. Special User APC queued without user-mode alertable state (Early Bird APC variant)",
            "4. KernelStack bounds mismatch vs Teb.DeallocationStack / KernelStackLimit"
        };
        result["mitigation_recommendations"] = {
            "Check for ETW Threat-Intelligence Kernel APC injection events",
            "Validate ApcState.Process matches owning EPROCESS"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

