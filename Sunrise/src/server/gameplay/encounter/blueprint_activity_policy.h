#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "server/gameplay/physics/world/activity_policy.h"

namespace sunrise::server::gameplay::encounter {

namespace world = ::sunrise::server::gameplay::physics::world;

/** One combatant read from an offline mission blueprint: where it spawns and which combatant it is. */
struct BlueprintSpawn final {
    world::Transform transform{};
    world::BlueprintRef combatProfile{};
};

/**
 * A data-driven mission policy — the encounter engine against Sunrise's IActivityPolicy boundary.
 *
 * The wave is split into ordered **phases**. `initialize` spawns phase 0 at its blueprint transforms
 * and sets the objective counter. `post_tick` watches committed `actorRemoved` events for the current
 * phase; when the phase is clear it spawns the next one, and when the last phase clears the objective
 * is complete. Everything goes through the typed `HostCommands` sink, so the whole multi-phase
 * encounter runs inside the deterministic logical `WorldRunner` with no client, wire, or wall-clock.
 *
 * Spawn transforms and phase layout come from `encounter_extract.py` (the offline blueprint tool):
 * a mission is a flat list of spawns plus a per-phase size (e.g. plaza wave, reinforcements, boss).
 */
class BlueprintActivityPolicy final : public world::IActivityPolicy {
public:
    static constexpr std::size_t kMaxSpawns = 64;
    static constexpr std::size_t kMaxPhases = 16;

    /**
     * Loads a multi-phase wave. `spawns` are laid out phase by phase; `phaseSizes[i]` is how many
     * spawns phase i owns (their sum is clamped to the number of spawns). Call before the world opens.
     */
    void configure(std::span<const BlueprintSpawn> spawns, std::span<const std::uint16_t> phaseSizes,
                   std::uint64_t objectiveCounterId, std::uint32_t bubble) noexcept;

    /**
     * Loads a small built-in wave for the in-game diagnostic hook, so a loaded mission can be driven
     * by this policy with no external blueprint. `contentBuild` must match the scene's content build
     * (the host validates the manifest against it before a world opens).
     */
    void configure_test(std::uint64_t contentBuild, std::uint32_t bubble) noexcept;

    /** The manifest for a given scene content build. The host validates this before opening a world. */
    [[nodiscard]] static world::ActivityPolicyManifest manifest_for(std::uint64_t contentBuild) noexcept;

    [[nodiscard]] world::ActivityPolicyManifest manifest() const noexcept override;
    [[nodiscard]] bool initialize(const world::ActivityPolicyContext& context,
                                  world::HostCommands& commands) noexcept override;
    void pre_tick(const world::PolicyTickContext& context,
                  world::HostCommands& commands) noexcept override;
    void post_tick(const world::PolicyTickContext& context,
                   std::span<const world::CommittedEvent> committedEvents,
                   world::HostCommands& commands) noexcept override;
    [[nodiscard]] bool save(world::IPolicyStateWriter& writer) const noexcept override;
    [[nodiscard]] bool load(world::IPolicyStateReader& reader) noexcept override;

    /** Inspection for tests and for a wave/phase state machine above this policy. */
    [[nodiscard]] std::size_t total_spawns() const noexcept { return spawnCount_; }
    [[nodiscard]] std::size_t phase_count() const noexcept { return phaseCount_; }
    [[nodiscard]] std::size_t current_phase() const noexcept { return currentPhase_; }
    [[nodiscard]] std::uint64_t alive_in_phase() const noexcept { return aliveInPhase_; }
    [[nodiscard]] bool objective_complete() const noexcept { return objectiveComplete_; }
    [[nodiscard]] world::ActorKey spawned_actor(std::size_t index) const noexcept;

private:
    /** Mutable per-tick state serialized for deterministic rollback. */
    struct PersistState final {
        std::uint64_t aliveInPhase{};
        std::uint64_t nextCommandId{};
        std::uint32_t currentPhase{};
        std::uint8_t objectiveComplete{};
    };

    [[nodiscard]] world::PolicyCommandMeta next_meta(world::TickId executeTick) noexcept;
    void spawn_phase(std::size_t phase, world::TickId executeTick,
                     world::HostCommands& commands) noexcept;
    [[nodiscard]] bool in_current_phase(const world::ActorKey& actor) const noexcept;

    std::array<BlueprintSpawn, kMaxSpawns> spawns_{};
    std::array<world::ActorKey, kMaxSpawns> spawnedActors_{};
    std::array<std::uint16_t, kMaxPhases> phaseSize_{};
    std::array<std::uint16_t, kMaxPhases> phaseStart_{};
    std::size_t spawnCount_{};
    std::size_t phaseCount_{};
    std::size_t currentPhase_{};
    std::uint64_t contentBuild_{};
    std::uint32_t bubble_{1};
    std::uint64_t objectiveCounterId_{1};
    std::uint64_t aliveInPhase_{};
    std::uint64_t nextCommandId_{1};
    bool objectiveComplete_{};
};

} // namespace sunrise::server::gameplay::encounter
