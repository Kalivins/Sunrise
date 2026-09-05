#pragma once

#include <cstdint>

#include "../../ui/runtime/settings.h"
#include "external/definition.h"

namespace sunrise::core::settings::client {

/** Wide enough to cover one encounter without reaching the next. */
inline constexpr std::uint32_t kDefaultEncounterPlacementRadius = 150;
/** Beyond this a table stops being proximity-driven and places its whole mission at once. */
inline constexpr std::uint32_t kMaximumEncounterPlacementRadius = 100'000;

/** A load this long has stopped making progress, so the spawn stops waiting for it. */
inline constexpr std::uint64_t kDefaultSpawnHoldMs = 30'000;
/** A load past this is a hang, not a slow machine, and holding the spawn would never end. */
inline constexpr std::uint64_t kMaximumSpawnHoldMs = 600'000;

/** Read-only Client settings parsed by Core. */
struct Settings {
    /** In-game UI visibility and input policy. */
    ui::runtime::Settings userInterface;
    /** Points the Client at a server outside this process. Off answers everything in process. */
    external::Settings externalServer;
    /**
     * Releases the world-transition fade channel at the in-world step.
     * The client only releases it on the player spawn, so this covers a spawn that never runs
     * and leaves the world black. On by default.
     */
    bool fadeRelease{true};
    /**
     * Forces the activity session's status 5-to-6 ready check.
     * Two of its five terms are client flags no host message reaches, so the host cannot open it.
     */
    bool forceJoinRequestReady{true};
    /**
     * Reports a public region as private to the region transition.
     * On, a public region loads solo. Off, it waits for a public activity host, which is the
     * route to the citizen join. A forced destination loads solo either way.
     */
    bool regionPrivate{false};
    /**
     * Forces the peer channel to connect directly instead of through a NAT relay.
     * The stock client always relays the gameplay peer channel, which cannot complete against a
     * loopback host with no relay server. On by default; a client stand-in for the peer relay.
     */
    bool suppressPeerRelay{true};
    /**
     * Pins the participation record to the replicated snapshot at `comp + 496`.
     * Off, the record is the local one at `comp + 1256`, whose spawn-gate byte no wire field
     * reaches.
     */
    bool pinReplicatedRecord{true};
    /**
     * Runs the player spawn after the world-transition fade is armed.
     * A spawn before the arm releases nothing, so the screen stays black. Settable because it is
     * the only thing that can turn an allowed spawn into a refusal.
     */
    bool holdSpawn{true};
    /**
     * Places a mission the authored squads it already carries, as the player comes within range of
     * each one. The table is data on disk, so a placement changes without a rebuild. Off by default
     * because it puts combatants in the world that nothing yet despawns.
     */
    bool encounterPlacementEnabled{false};
    /**
     * Draws the authored rows as markers in the world. Surveying happens on foot, so what is
     * already authored belongs in front of the surveyor rather than in a separate plan.
     */
    bool encounterMarkersEnabled{false};
    /** Horizontal field of view the markers project through, in degrees. */
    std::uint32_t encounterMarkerFov{85};
    /**
     * Metres from an authored position at which its squad is placed. The content chooses how far
     * apart a mission spreads its encounters, so no compiled constant is right for every table.
     */
    std::uint32_t encounterPlacementRadius{kDefaultEncounterPlacementRadius};
    /** How long the spawn waits for a load. `hold_spawn` decides whether it waits at all. */
    std::uint64_t spawnHoldMs{kDefaultSpawnHoldMs};
};

} // namespace sunrise::core::settings::client
