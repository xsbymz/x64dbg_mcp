#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_ept_page_walker_routes(c_http_router& router) {
    router.post("/api/ept_walk/simulate_translation", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string gpaStr = body.value("guest_physical_address", "0x1000000");
        json result;
        result["guest_physical_address"] = gpaStr;
        result["ept_4level_paging_hierarchy"] = {
            {"EPTP", "EPT Pointer in VMCS (Contains physical base address of PML4 table and memory type)"},
            {"PML4E", "PML4 Entry (Bits 47:39 of GPA): specifies physical base of EPT Page-Directory-Pointer Table (PDPT)"},
            {"PDPTE", "PDP Table Entry (Bits 38:30 of GPA): specifies physical base of EPT Page Directory (PD) or 1GB Page"},
            {"PDE", "Page Directory Entry (Bits 29:21 of GPA): specifies physical base of EPT Page Table (PT) or 2MB Page"},
            {"PTE", "Page Table Entry (Bits 20:12 of GPA): specifies Host Physical Address (HPA) base of 4KB Page"},
            {"Offset", "Bits 11:0 of GPA: byte index within 4KB physical page frame"}
        };
        result["ept_permission_bits"] = {
            {"Bit_0", "Read access (R)"},
            {"Bit_1", "Write access (W)"},
            {"Bit_2", "Execute access (X) / Execute access for user-mode if Mode-Based Execution Control (MBEC) active"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/ept_walk/detect_hidden_hooks", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["ept_hooking_signature"] = {
            "1. Split EPT permissions: Read/Write mapped to original page, Execute mapped to hooked shadow page",
            "2. Read/Write memory inspection sees clean code; execution jumps into rootkit trampoline without trigger",
            "3. Detection: Force single-stepping across EPT page boundaries and monitor MTF (Monitor Trap Flag) VMEXITs"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
