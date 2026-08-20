#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_paging_walker_routes(c_http_router& router) {
    router.post("/api/paging/walk_virtual_address", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string vaStr = body.value("virtual_address", "0x7FFE0000");
        uint64_t va = 0;
        try { va = std::stoull(vaStr, nullptr, 16); } catch(...) { va = 0x7FFE0000; }

        json result;
        result["virtual_address"] = vaStr;
        result["canonical_address"] = ((va >> 47) == 0 || (va >> 47) == 0x1FFFF);

        // 4-level paging indices
        result["indices_4level"] = {
            {"pml4_index", (va >> 39) & 0x1FF},
            {"pdpt_index", (va >> 30) & 0x1FF},
            {"pd_index",   (va >> 21) & 0x1FF},
            {"pt_index",   (va >> 12) & 0x1FF},
            {"page_offset", va & 0xFFF}
        };

        // 5-level paging indices (LA57)
        result["indices_5level_la57"] = {
            {"pml5_index", (va >> 48) & 0x1FF},
            {"pml4_index", (va >> 39) & 0x1FF},
            {"pdpt_index", (va >> 30) & 0x1FF},
            {"pd_index",   (va >> 21) & 0x1FF},
            {"pt_index",   (va >> 12) & 0x1FF},
            {"page_offset", va & 0xFFF}
        };

        result["entry_flags_reference"] = {
            {"P (Bit 0)", "Present"},
            {"R/W (Bit 1)", "Read/Write (0 = Read-only, 1 = Read/Write)"},
            {"U/S (Bit 2)", "User/Supervisor (0 = Supervisor mode, 1 = User mode)"},
            {"PWT (Bit 3)", "Page-level Write-Through"},
            {"PCD (Bit 4)", "Page-level Cache Disable"},
            {"A (Bit 5)", "Accessed"},
            {"D (Bit 6)", "Dirty"},
            {"PS (Bit 7)", "Page Size (1 = Large Page 2MB/1GB)"},
            {"G (Bit 8)", "Global (TLB persistence across CR3 reload)"},
            {"NX/XD (Bit 63)", "No-Execute / Execute-Disable"}
        };

        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/paging/inspect_pcid_layout", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["pcid_cr3_layout"] = {
            {"Bits_11_0", "PCID (Process-Context Identifier: 12-bit address space ID)"},
            {"Bits_51_12", "Physical base address of PML4 table (page-aligned)"},
            {"Bit_63", "NO_FLUSH (If set to 1 on CR3 write, preserves TLB entries tagged with current PCID)"}
        };
        result["kpti_pcid_isolation"] = {
            "Windows KPTI (Kernel Page Table Isolation) maintains dual CR3 values per process:",
            "User-mode CR3 (PCID = N | 0x000): Maps user-space + minimal trampoline",
            "Kernel-mode CR3 (PCID = N | 0x800): Maps entire virtual address space including kernel structures"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
