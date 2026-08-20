#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_cs_beacon_routes(c_http_router& router) {
    router.post("/api/cs_beacon/scan_memory", [](const httplib::Request& req, httplib::Response& res) {
        json body; try{body=json::parse(req.body);}catch(...){body=json::object();}
        DWORD pid = body.value("pid",(DWORD)0);
        json result; result["pid"]=pid; result["hits"]=json::array();
        // CS beacon config magic bytes and XOR key patterns
        // Old CS (<=4.0): XOR key 0x69 config
        // New CS: more complex encoding but config block starts with specific magic
        const BYTE cs_xor_key = 0x69;
        // Known beacon config "magic" after XOR decode: 0x0001 = payload type field
        HANDLE hProc = pid ? OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,pid) : GetCurrentProcess();
        if (!hProc && pid) { result["error"]="OpenProcess failed"; res.set_content(result.dump(),"application/json"); return; }
        SYSTEM_INFO si={}; GetSystemInfo(&si);
        BYTE* addr=(BYTE*)si.lpMinimumApplicationAddress;
        BYTE* maxAddr=(BYTE*)si.lpMaximumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi={};
        while (addr < maxAddr) {
            if (!VirtualQueryEx(hProc,addr,&mbi,sizeof(mbi))) { addr+=0x1000; continue; }
            if (mbi.State==MEM_COMMIT && mbi.Type==MEM_PRIVATE && mbi.RegionSize>256 &&
                (mbi.Protect==PAGE_READWRITE||mbi.Protect==PAGE_READONLY||mbi.Protect==PAGE_EXECUTE_READWRITE)) {
                std::vector<BYTE> buf(std::min(mbi.RegionSize,(SIZE_T)0x100000));
                SIZE_T read=0;
                if (ReadProcessMemory(hProc,mbi.BaseAddress,buf.data(),(SIZE_T)buf.size(),&read) && read>256) {
                    // Scan for CS config XOR pattern: after XOR 0x69, first 2 bytes = 0x0001 (BeaconType)
                    for (SIZE_T i=0;i+8<=read;i++) {
                        BYTE b0=buf[i]^cs_xor_key, b1=buf[i+1]^cs_xor_key;
                        BYTE b2=buf[i+2]^cs_xor_key, b3=buf[i+3]^cs_xor_key;
                        // Check for config block: type=1 (HTTP/S beacon), length=2, value=1 or 2
                        if ((b0==0&&b1==1&&b2==0&&b3==2) || (b0==0&&b1==2&&b2==0&&b3==4)) {
                            json hit;
                            hit["address"] = (uintptr_t)mbi.BaseAddress+i;
                            hit["xor_key"] = cs_xor_key;
                            hit["possible_config_type"] = (int)(b0<<8|b1);
                            result["hits"].push_back(hit);
                            if (result["hits"].size()>=10) goto done;
                        }
                    }
                }
            }
            addr=(BYTE*)mbi.BaseAddress+mbi.RegionSize;
        }
        done:
        if (pid && hProc) CloseHandle(hProc);
        result["hit_count"] = result["hits"].size();
        result["beacon_types"] = {{"0","Payload Type"},{"1","HTTP Beacon"},{"2","HTTPS Beacon"},{"8","SMB Beacon"},{"16","TCP Beacon"},{"32","External C2"}};
        res.set_content(result.dump(),"application/json");
    });
    router.post("/api/cs_beacon/extract_config", [](const httplib::Request& req, httplib::Response& res) {
        json body; try{body=json::parse(req.body);}catch(...){body=json::object();}
        json result;
        result["config_fields"] = {
            {"0x0001","BeaconType (1=HTTP,2=HTTPS,8=SMB,16=TCP,32=ExternalC2)"},
            {"0x0002","Port"},{"0x0003","SleepTime"},{"0x0004","MaxGetSize"},
            {"0x0005","Jitter"},{"0x0006","MaxDNS"},{"0x0007","PublicKey"},
            {"0x0008","C2Server"},{"0x0009","UserAgent"},{"0x000A","HttpPostUri"},
            {"0x000B","Malleable_C2_Instructions"},{"0x000D","SpawnTo x86"},
            {"0x000E","SpawnTo x64"},{"0x001A","PipeName (SMB)"},
            {"0x001B","DNS_Idle"},{"0x001C","DNS_Sleep"},
            {"0x0023","HttpGet_Verb"},{"0x0024","HttpPost_Verb"}
        };
        result["extraction_steps"] = {
            "1. Find config blob start (XOR 0x69 decode -> first field = 0x0001)",
            "2. Each field: 2-byte type + 2-byte length + n-byte value",
            "3. Decode all fields until sentinel (type=0) or end of block",
            "4. C2 server field (0x0008) reveals C2 infrastructure"
        };
        result["sleep_obfuscation_variants"] = {
            "Ekko: RtlCreateTimer + ROP chain (VirtualProtect+SystemFunction032+memcpy+VirtualProtect+NtContinue)",
            "Foliage: SetWaitableTimer + TpAllocTimer APC to decrypt+execute+re-encrypt",
            "Gargoyle: timer-based APC with RWX flip using VirtualAlloc+memcpy gadgets"
        };
        res.set_content(result.dump(),"application/json");
    });
    router.post("/api/cs_beacon/detect_sleep_obfuscation", [](const httplib::Request& req, httplib::Response& res) {
        json body; try{body=json::parse(req.body);}catch(...){body=json::object();}
        DWORD pid = body.value("pid",(DWORD)0);
        json result; result["sleep_obfuscation_indicators"]=json::array();
        // Look for RX->RW->RX transitions in memory
        HANDLE hProc = pid ? OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,pid) : GetCurrentProcess();
        int rwxCount=0, rx2rwCount=0;
        if (hProc) {
            BYTE* addr=0; MEMORY_BASIC_INFORMATION mbi={};
            while (VirtualQueryEx(hProc,addr,&mbi,sizeof(mbi))) {
                if (mbi.State==MEM_COMMIT && mbi.Type==MEM_PRIVATE) {
                    if (mbi.Protect==PAGE_EXECUTE_READWRITE) rwxCount++;
                }
                addr=(BYTE*)mbi.BaseAddress+mbi.RegionSize;
                if (addr<(BYTE*)mbi.BaseAddress) break;
            }
            if (pid) CloseHandle(hProc);
        }
        result["rwx_private_regions"] = rwxCount;
        result["indicators"] = {
            {"RWX_private_memory","Non-zero count of private RWX pages = suspicious (Gargoyle/Ekko pattern)"},
            {"waitable_timers","Check CreateWaitableTimer handles — beacon creates timer for sleep cycle"},
            {"thread_pool_apc","Look for TpAllocTimer/TpSetTimer calls in thread pool API trace"}
        };
        res.set_content(result.dump(),"application/json");
    });
}
} // namespace handlers
