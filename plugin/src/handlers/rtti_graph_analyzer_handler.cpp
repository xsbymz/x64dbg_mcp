#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_rtti_graph_analyzer_routes(c_http_router& router) {
    router.post("/api/rtti_graph/build_hierarchy_graph", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string vtableAddr = body.value("vtable_address", "");
        json result;
        result["vtable_address"] = vtableAddr;
        result["msvc_rtti_structure_graph"] = {
            {"vtable_minus_8", "Pointer to _RTTICompleteObjectLocator descriptor preceding vtable[0]"},
            {"_RTTICompleteObjectLocator", {
                {"signature", "0 = 32-bit, 1 = 64-bit (relative 32-bit offsets to image base)"},
                {"offset", "Offset of this vtable in complete class instance"},
                {"cdOffset", "Constructor displacement offset"},
                {"pTypeDescriptor", "RVA of type_info descriptor containing mangled class name (e.g. .?AVMyClass@@)"},
                {"pClassDescriptor", "RVA of _RTTIClassHierarchyDescriptor"}
            }},
            {"_RTTIClassHierarchyDescriptor", {
                {"signature", "Always 0"},
                {"attributes", "0x01 = multiple inheritance, 0x02 = virtual inheritance, 0x04 = ambiguous base"},
                {"numBaseClasses", "Total count of base classes in inheritance tree"},
                {"pBaseClassArray", "RVA of array of _RTTIBaseClassDescriptor pointers"}
            }}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/rtti_graph/demangle_type_names", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string mangledName = body.value("mangled_name", ".?AVruntime_error@std@@");
        json result;
        result["mangled_name"] = mangledName;
        result["demangling_rule"] = "Strip prefix '.?AV' and suffix '@@', resolve namespaces separated by '@' in reverse order";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

