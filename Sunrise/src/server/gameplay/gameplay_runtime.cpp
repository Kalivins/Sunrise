#include "gameplay_runtime.h"

#include <array>
#include <cstddef>
#include <cstdio>

#include "association/association_host.h"
#include "core/logging/log.h"
#include "dtls/dtls_host.h"
#include "endpoint/gameplay_endpoint.h"
#include "group/group_host.h"
#include "peer/peer_transport.h"
#include "physics/host/physics_session.h"
#include "physics/host/runtime.h"
#include "state/build_data/runtime.h"
#include "state/build_data/scenarios/definition.h"

namespace sunrise::server::gameplay {
namespace {

/**
 * DIAGNOSTIC (one-shot at boot): logs each published scenario layout's name and its non-zero bubble
 * name hashes. The client names its arrival bubble by hash, so this maps a destination (e.g.
 * Homecoming / city_tower_d16_t0) to the hash the slice-set selector looks up. Read-only.
 */
void dump_scenario_layouts() noexcept {
    static std::array<state::build_data::scenarios::Definition,
                      state::build_data::scenarios::kDefinitionCapacity>
        scratch{};
    std::size_t count = 0;
    if (!state::build_data::snapshot_scenario_layouts(scratch, count)) {
        return;
    }
    for (std::size_t index = 0; index < count; ++index) {
        const state::build_data::scenarios::Definition& layout = scratch[index];
        std::array<char, 256> line{};
        int written = std::snprintf(line.data(), line.size(),
                                    "ev=builddata stage=layout name=%.*s bubbles=%u hashes=",
                                    static_cast<int>(layout.nameLength), layout.name.data(),
                                    static_cast<unsigned>(layout.bubbleCount));
        const std::size_t bubbles = layout.bubbleCount < layout.bubbleHashes.size()
                                        ? layout.bubbleCount
                                        : layout.bubbleHashes.size();
        for (std::size_t bubble = 0; bubble < bubbles && written > 0
                                     && static_cast<std::size_t>(written) < line.size();
             ++bubble) {
            written += std::snprintf(line.data() + written,
                                     line.size() - static_cast<std::size_t>(written), "%s0x%08X",
                                     bubble == 0 ? "" : ",",
                                     static_cast<unsigned>(layout.bubbleHashes[bubble]));
        }
        if (written > 0) {
            const std::size_t length = static_cast<std::size_t>(written) < line.size()
                                           ? static_cast<std::size_t>(written)
                                           : line.size() - 1;
            core::log::write(core::log::Channel::server, core::log::Level::info,
                             {line.data(), length});
        }
    }
}

} // namespace

/** Binds the gameplay endpoint for the configured topology. */
bool initialize() noexcept {
    association::reset();
    dtls::reset();
    peer::reset();
    group::reset();
    if (!endpoint::initialize()) {
        return false;
    }
    // The endpoint binds first. No transport path reaches the host yet, so a host that cannot
    // allocate must not stop the channel from carrying everything that does not need one.
    static_cast<void>(physics::host::runtime::initialize());
    return true;
}

/** Runs one bounded gameplay slice. */
void service(std::uint64_t now) noexcept {
    // Fires once, the first slice after the scenario layouts are published.
    static bool g_layoutsDumped = false;
    if (!g_layoutsDumped && state::build_data::scenario_layout_count() != 0) {
        g_layoutsDumped = true;
        dump_scenario_layouts();
    }
    endpoint::service(now);
    // The retries run before the send so anything they queue leaves in this slice.
    group::service(now);
    peer::service(now);
    // Last, because it reads the admitted set the two calls above have already settled. It emits
    // nothing on the wire, so its position cannot delay a queued send.
    physics::host::session::service(now);
}

/** Stops the endpoint and clears every association and peer. */
void shutdown() noexcept {
    endpoint::shutdown();
    // The worlds close before the host does, or their State contexts are stranded.
    physics::host::session::reset();
    physics::host::runtime::shutdown();
    peer::reset();
    group::reset();
    dtls::reset();
    association::reset();
}

} // namespace sunrise::server::gameplay
