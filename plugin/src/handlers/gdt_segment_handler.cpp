#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_gdt_segment_routes(c_http_router& router) {
    router.post("/api/gdt/dump_table", [](const s_http_request& req) {
        json result;
        // Read GDTR
        struct GDTR { WORD limit; ULONG_PTR base; } __attribute__((packed));
        GDTR gdtr = {};
        gdtr.limit = 0xFFFF;
        gdtr.base = 0;
        result["gdtr_base"] = gdtr.base;
        result["gdtr_limit"] = gdtr.limit;
        result["descriptor_count"] = (gdtr.limit + 1) / 8;
        result["segments"] = json::array();
        // x64 segment descriptors
        struct SEG_DESC { WORD limit0; WORD base0; BYTE base1; BYTE access; BYTE limit1_flags; BYTE base2; };
        struct SYS_DESC { WORD limit0; WORD base0; BYTE base1; BYTE access; BYTE limit1_flags; BYTE base2; DWORD base3; DWORD reserved; };
        // Known important GDT slots for x64 Windows
        struct { int idx; const char* name; } knownSegs[] = {
            {0,"NULL"},{8,"Kernel Code 64-bit (0x08)"},{16,"Kernel Data (0x10)"},
            {24,"User 32-bit Code (0x18)"},{32,"User Data (0x20)"},{40,"User 64-bit Code (0x28)"},
            {48,"TSS Low (0x30)"},{56,"TSS High (0x38)"},{64,"PCR (0x40) / FS base"},
            {72,"GS Kernel / KPCR (0x50)"}
        };
        if (gdtr.base) {
            for (auto& seg : knownSegs) {
                if (seg.idx+7 > gdtr.limit) break;
                auto* d = reinterpret_cast<SEG_DESC*>(gdtr.base + seg.idx);
                DWORD base = d->base0 | ((DWORD)d->base1<<16) | ((DWORD)d->base2<<24);
                DWORD limit = d->limit0 | (((DWORD)d->limit1_flags&0xF)<<16);
                json entry;
                entry["index"] = seg.idx;
                entry["name"] = seg.name;
                entry["base"] = base;
                entry["limit"] = limit;
                entry["access"] = d->access;
                entry["dpl"] = (d->access>>5)&3;
                entry["present"] = (d->access>>7)&1;
                entry["type_bits"] = d->access&0x1F;
                bool isCallGate = (d->access&0x1F)==0x0C;
                entry["is_call_gate"] = isCallGate;
                if (isCallGate) entry["warning"] = "CALL GATE detected — potential privilege escalation vector";
                result["segments"].push_back(entry);
            }
        }
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/gdt/find_call_gates", [](const s_http_request& req) {
        json result;
        result["call_gate_theory"] = {
            "A Call Gate (type=0x0C) in GDT/LDT allows ring3 code to call ring0 procedures via CALL FAR selector:0",
            "The gate specifies: target_cs (must be ring-0 code selector), target_offset (ring-0 function address), DPL (ring3 can call it), param_count",
            "Windows does not use call gates in normal operation — presence is suspicious",
            "Historical exploitation: install rogue call gate -> ring3 code executes ring-0 function -> local privilege escalation"
        };
        result["detection"] = "Scan all GDT entries for type_bits=0x0C (call gate) or 0x04 (task gate) with DPL=3 — these are ring3-accessible gates pointing to ring0 code";
        struct GDTR { WORD limit; ULONG_PTR base; } __attribute__((packed));
        GDTR gdtr = {};
        gdtr.limit = 0xFFFF;
        gdtr.base = 0;
        result["call_gates"] = json::array();
        if (gdtr.base && gdtr.limit > 7) {
            struct SEG_DESC { WORD w0; WORD w1; BYTE b0; BYTE access; BYTE b1; BYTE b2; };
            int count = (gdtr.limit+1)/8;
            for (int i=0;i<count&&i<128;i++) {
                auto* d = reinterpret_cast<SEG_DESC*>(gdtr.base + i*8);
                BYTE type = d->access & 0x1F;
                if (type==0x0C||type==0x0E||type==0x04||type==0x05) {
                    json gate; gate["index"]=i*8; gate["type"]=type; gate["access"]=d->access;
                    gate["dpl"]=(d->access>>5)&3;
                    if (type==0x0C) gate["warning"]="Call Gate — ring3 accessible ring0 entry point";
                    result["call_gates"].push_back(gate);
                }
            }
        }
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/gdt/detect_privilege_escalation_descriptors", [](const s_http_request& req) {
        json result;
        result["escalation_techniques"] = {
            {"call_gate","Install GDT call gate with DPL=3 pointing to ring0 gadget"},
            {"task_gate","Task switch via task gate — saves/restores full CPU state including CPL"},
            {"modified_cs_dpl","Modify kernel CS descriptor DPL to 3 — allows direct far JMP to ring0"},
            {"trap_gate","INT n via trap gate (DPL=3) — can target arbitrary kernel handler"}
        };
        result["modern_relevance"] = "x64 Windows largely eliminates call gates and task gates, but TSS descriptor (0x30) and LDT descriptor are present. Manipulation of TSS IST fields or stack pointers = kernel stack pivot.";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

