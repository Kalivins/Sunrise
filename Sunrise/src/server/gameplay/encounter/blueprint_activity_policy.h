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
 * A minimal, data-driven mission policy — the encounter-engine vertical slice against Sunrise's
 * IActivityPolicy boundary.
 *
 * On `initialize` it spawns one wave of combatants at their real blueprint transforms, gives each a
 * combat profile, arms a trigger volume over the wave, and sets an objective counter to the wave
 * size. On `post_tick` it watches committed `actorRemoved` events for the actors it spawned; each
 * removal decrements the objective, and when the wave is clear the objective is marked complete.
 *
 * Everything it does goes through the existing typed `HostCommands` sink, so the whole encounter runs
 * inside the deterministic logical `WorldRunner` with no client, wire, or wall-clock input. The wave
 * positions come from `encounter_extract.py` (the offline blueprint tool).
 */
class BlueprintActivityPolicy final : public world::IActivityPolicy {
public:
    static constexpr std::size_t kMaxSpawns = 32;

    /** Loads one wave. Call before the world opens. `spawns` beyond kMaxSpawns are ignored. */
    void configure(std::span<const BlueprintSpawn> spawns, std::uint64_t objectiveCounterId,
                   std::uint32_t bubble) noexcept;

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

    /** Inspection for tests and for driving a wave/phase state machine above this policy. */
    [[nodiscard]] std::size_t wave_size() const noexcept { return spawnCount_; }
    [[nodiscard]] std::uint64_t alive_count() const noexcept { return aliveCount_; }
    [[nodiscard]] bool objective_complete() const noexcept { return objectiveComplete_; }
    [[nodiscard]] world::ActorKey spawned_actor(std::size_t index) const noexcept;

private:
    /** Mutable per-tick state serialized for deterministic rollback. */
    struct PersistState final {
        std::uint64_t aliveCount{};
        std::uint64_t nextCommandId{};
        std::uint8_t objectiveComplete{};
    };

    [[nodiscard]] world::PolicyCommandMeta next_meta(world::TickId executeTick) noexcept;

    std::array<BlueprintSpawn, kMaxSpawns> spawns_{};
    std::array<world::ActorKey, kMaxSpawns> spawnedActors_{};
    std::size_t spawnCount_{};
    std::uint32_t bubble_{1};
    std::uint64_t objectiveCounterId_{1};
    std::uint64_t aliveCount_{};
    std::uint64_t nextCommandId_{1};
    bool objectiveComplete_{};
};

} // namespace sunrise::server::gameplay::encounter
