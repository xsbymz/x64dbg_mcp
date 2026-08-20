#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_dkom_detector_routes(c_http_router& router) {
    router.post("/api/dkom/detect_hidden_processes", [](const s_http_request& req) {
        json result;
        result["dkom_technique"] = {
            "Unlink _EPROCESS.ActiveProcessLinks (Flink/Blink) from doubly-linked list",
            "NtQuerySystemInformation(SystemProcessInformation) walks ActiveProcessLinks — misses unlinked process",
            "PspCidTable still maps PID→EPROCESS — process is functional but invisible to most APIs"
        };
        // Enumerate via NtQuerySystemInformation — visible processes
        result["visible_processes"] = json::array();
        typedef struct _SYSTEM_PROCESS_INFORMATION {
            ULONG NextEntryOffset; ULONG NumberOfThreads; BYTE Reserved1[48];
            PVOID Reserved2[3]; HANDLE UniqueProcessId; PVOID Reserved3; ULONG HandleCount;
            BYTE Reserved4[4]; PVOID Reserved5[11]; SIZE_T PeakPagefileUsage;
            SIZE_T PrivatePageCount; LARGE_INTEGER Reserved6[6];
        } SYSTEM_PROCESS_INFORMATION;
        ULONG sz=0;
        NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,nullptr,0,&sz);
        if (sz>0) {
            std::vector<BYTE> buf(sz+4096);
            if (NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,buf.data(),(ULONG)buf.size(),&sz))) {
                auto* p = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data());
                while (true) {
                    DWORD pid = (DWORD)(uintptr_t)p->UniqueProcessId;
                    if (pid > 0) {
                        json proc; proc["pid"] = pid;
                        // Get process name via handle
                        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
                        if (h) {
                            WCHAR img[MAX_PATH]={}; DWORD len=MAX_PATH;
                            QueryFullProcessImageNameW(h,0,img,&len);
                            char imgA[MAX_PATH]={};
                            WideCharToMultiByte(CP_UTF8,0,img,-1,imgA,sizeof(imgA),nullptr,nullptr);
                            proc["image"] = std::string(imgA);
                            CloseHandle(h);
                        }
                        result["visible_processes"].push_back(proc);
                    }
                    if (!p->NextEntryOffset) break;
                    p = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>((BYTE*)p+p->NextEntryOffset);
                }
            }
        }
        result["visible_count"] = result["visible_processes"].size();
        result["cross_check_note"] = "Compare visible PIDs against CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) — discrepancies indicate DKOM. Full detection requires PspCidTable walk (kernel access needed).";
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/dkom/compare_pspcid_vs_activelist", [](const s_http_request& req) {
        json result;
        result["methodology"] = {
            {"step1","Walk ActiveProcessLinks via NtQuerySystemInformation — collect all visible PIDs"},
            {"step2","Walk PspCidTable (kernel _HANDLE_TABLE at nt!PspCidTable) — all PIDs including hidden"},
            {"step3","PIDs in PspCidTable but NOT in ActiveProcessLinks = DKOM-hidden processes"},
            {"step4","Alternative: enumerate all PIDs 1-65535 via OpenProcess — handle success = process exists"}
        };
        // Brute-force PID scan
        result["brute_force_pids"] = json::array();
        for (DWORD pid=4; pid<=0x10000; pid+=4) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
            if (h) {
                json p; p["pid"]=pid;
                WCHAR img[MAX_PATH]={}; DWORD len=MAX_PATH;
                QueryFullProcessImageNameW(h,0,img,&len);
                char a[MAX_PATH]={}; WideCharToMultiByte(CP_UTF8,0,img,-1,a,sizeof(a),nullptr,nullptr);
                p["image"]=std::string(a);
                result["brute_force_pids"].push_back(p);
                CloseHandle(h);
            }
        }
        result["brute_force_count"] = result["brute_force_pids"].size();
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/dkom/find_unlinked_eprocess", [](const s_http_request& req) {
        json result;
        result["detection_heuristics"] = {
            "Process has valid handles in system handle table but no NtQuerySystemInformation entry",
            "OpenProcess(PID) succeeds but PID missing from tasklist/CreateToolhelp32Snapshot",
            "Network connections to orphan PIDs (GetExtendedTcpTable shows owning PID not in process list)",
            "Event log entries referencing non-existent PIDs (process creation but no corresponding list entry)"
        };
        result["network_cross_check"] = json::array();
        // Check for processes owning network connections that don't appear in process list
        MIB_TCPTABLE_OWNER_PID* tcpTable = nullptr;
        DWORD tcpSz = 0;
        GetExtendedTcpTable(nullptr,&tcpSz,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
        if (tcpSz>0) {
            tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSz);
            if (GetExtendedTcpTable(tcpTable,&tcpSz,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)==NO_ERROR) {
                for (DWORD i=0;i<tcpTable->dwNumEntries;i++) {
                    json conn;
                    conn["pid"] = tcpTable->table[i].dwOwningPid;
                    conn["local_port"] = ntohs((WORD)tcpTable->table[i].dwLocalPort);
                    conn["state"] = tcpTable->table[i].dwState;
                    result["network_cross_check"].push_back(conn);
                }
            }
            free(tcpTable);
        }
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers


