#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_irp_inspector_routes(c_http_router& router) {
    router.post("/api/irp/list_pending", [](const s_http_request& req) {
        json result;
        result["irp_structure_layout"] = {
            {"Type", "IO_TYPE_IRP (0x06)"},
            {"Size", "Total size of IRP header and stack locations"},
            {"MdlAddress", "Pointer to Memory Descriptor List (MDL) for direct I/O"},
            {"Flags", "IRP_NOCACHE, IRP_PAGING_IO, IRP_SYNCHRONOUS_API, etc."},
            {"AssociatedIrp", "SystemBuffer for buffered I/O or master IRP for compound requests"},
            {"ThreadListEntry", "Links IRP to issuing thread's IrpList"},
            {"IoStatus", "IO_STATUS_BLOCK containing final Status and Information byte count"},
            {"CurrentLocation", "Index of current IO_STACK_LOCATION frame"},
            {"Cancel", "Boolean flag indicating request cancellation"},
            {"CancelRoutine", "Driver-provided cancellation callback pointer"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/irp/decode_stack_locations", [](const s_http_request& req) {
        json result;
        result["io_stack_location_fields"] = {
            {"MajorFunction", "IRP_MJ_* request identifier"},
            {"MinorFunction", "Sub-operation (e.g. IRP_MN_START_DEVICE for PnP)"},
            {"Flags", "SL_* modifier flags"},
            {"Control", "SL_INVOKE_ON_SUCCESS, SL_INVOKE_ON_ERROR, SL_INVOKE_ON_CANCEL"},
            {"Parameters", "Union of operation-specific arguments (DeviceIoControl, Read, Write, Create)"},
            {"DeviceObject", "Target DEVICE_OBJECT for this driver layer in stack"},
            {"FileObject", "Associated IO_FILE_OBJECT representation"},
            {"CompletionRoutine", "Driver callback executed during IoCompleteRequest unwind"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/irp/detect_suspicious_completion_routines", [](const s_http_request& req) {
        json result;
        result["completion_routine_threats"] = {
            "1. Completion routine pointer pointing to unbacked pool memory (rootkit filter)",
            "2. Completion routine modifying IoStatus.Status to STATUS_SUCCESS for hidden files/processes",
            "3. Stalled asynchronous IRPs held indefinitely for covert driver-to-driver IPC channels",
            "4. Missing IoSetCompletionRoutine cleanup resulting in stale kernel callbacks"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

