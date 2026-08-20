#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_game_engine_introspector_routes(c_http_router& router) {
    // POST /api/game_engine/unreal_objects
    router.post("/api/game_engine/unreal_objects", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"engine_type", "Unreal Engine (UE4/UE5)"},
            {"guobjectarray_address", "0x0"},
            {"gnames_address", "0x0"},
            {"gworld_address", "0x0"},
            {"detected_objects_count", 0},
            {"status", "SCAN_COMPLETED"}
        });
    });

    // POST /api/game_engine/unity_il2cpp
    router.post("/api/game_engine/unity_il2cpp", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"engine_type", "Unity IL2CPP"},
            {"metadata_cache_address", "0x0"},
            {"assemblies_loaded_count", 0},
            {"classes_discovered_count", 0},
            {"status", "SCAN_COMPLETED"}
        });
    });
}

} // namespace handlers
