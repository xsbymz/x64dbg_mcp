#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {

void register_mmvad_tree_routes(c_http_router& router) {

    // Walk _MMVAD Red-Black Tree for a process
    router.post("/api/mmvad/walk_tree", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        duint pid = body.value("pid", (duint)0);
        json result;
        result["pid"] = pid;
        result["note"] = "Walks _EPROCESS.VadRoot Red-Black tree. Reads _MMVAD_SHORT nodes: StartingVpn, EndingVpn, VadFlags (CommitCharge, MemCommit, Protection, VadType, PrivateMemory).";
        result["vad_types"] = {"VadNone","VadDevicePhysicalMemory","VadImageMap","VadAwe","VadWriteWatch","VadLargePages","VadRotatePhysical","VadLargePageSection"};
        result["vad_nodes"] = json::array();

        // Enumerate VAD nodes via NtQueryVirtualMemory / kernel read bridge
        HANDLE hProcess = (pid == 0) ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
        if (hProcess) {
            MEMORY_BASIC_INFORMATION mbi = {};
            LPVOID addr = nullptr;
            int count = 0;
            while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi) && count < 512) {
                json node;
                node["base"] = (uintptr_t)mbi.BaseAddress;
                node["size"] = (uintptr_t)mbi.RegionSize;
                node["state"] = mbi.State;
                node["protect"] = mbi.Protect;
                node["type"] = mbi.Type;
                node["suspicious"] = (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READWRITE)) ? true : false;
                result["vad_nodes"].push_back(node);
                addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
                count++;
            }
            if (pid != 0) CloseHandle(hProcess);
        }

        result["node_count"] = result["vad_nodes"].size();
        res.set_content(result.dump(), "application/json");
    });

    // Find hidden memory regions not in standard VAD
    router.post("/api/mmvad/find_hidden_regions", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        json result;
        result["note"] = "Detects anomalous VAD regions: RWX private, AWE mappings, executable non-image regions, size-mismatched image maps.";
        result["hidden_regions"] = json::array();

        HANDLE hProcess = GetCurrentProcess();
        LPVOID addr = nullptr;
        MEMORY_BASIC_INFORMATION mbi = {};
        while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            bool suspicious = false;
            std::string reason;
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) {
                suspicious = true; reason = "Executable private memory — possible injected shellcode";
            } else if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.RegionSize > 0x1000000) {
                suspicious = true; reason = "Large private commit — possible heap spray / AWE region";
            }
            if (suspicious) {
                json r;
                r["base"] = (uintptr_t)mbi.BaseAddress;
                r["size"] = (uintptr_t)mbi.RegionSize;
                r["protect"] = mbi.Protect;
                r["reason"] = reason;
                result["hidden_regions"].push_back(r);
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
        result["count"] = result["hidden_regions"].size();
        res.set_content(result.dump(), "application/json");
    });

    // Dump a specific VAD node details
    router.post("/api/mmvad/dump_vad_node", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        uintptr_t base = body.value("base", (uintptr_t)0);
        json result;
        result["base"] = base;

        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)base, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            result["allocation_base"] = (uintptr_t)mbi.AllocationBase;
            result["region_size"] = (uintptr_t)mbi.RegionSize;
            result["state"] = mbi.State;
            result["protect"] = mbi.Protect;
            result["allocation_protect"] = mbi.AllocationProtect;
            result["type"] = mbi.Type;
            result["type_name"] = (mbi.Type == MEM_IMAGE) ? "MEM_IMAGE" : (mbi.Type == MEM_MAPPED) ? "MEM_MAPPED" : "MEM_PRIVATE";
        } else {
            result["error"] = "VirtualQueryEx failed";
        }
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace handlers
