#include "blueprint_activity_policy.h"

#include <cstring>

#include "server/gameplay/physics/world/command_queue.h"
#include "server/gameplay/physics/world/host_command.h"

namespace sunrise::server::gameplay::encounter {
namespace {

/** Stable nonzero identity for this policy's blueprint and owner (headers reject zero fields). */
constexpr world::BlueprintRef kPolicyBlueprint{0xE0C0DE01U, 1U};
constexpr world::PolicyOwnerId kPolicyOwner{0x454E4331U}; // 'ENC1'
constexpr std::uint64_t kTriggerId{1U};

/** Commands submitted during initialize execute on the first fixed tick. */
constexpr world::TickId kFirstExecuteTick{1U};

[[nodiscard]] bool ok(world::CommandSubmitStatus status) noexcept {
    return status == world::CommandSubmitStatus::accepted
           || status == world::CommandSubmitStatus::coalesced;
}

} // namespace

void BlueprintActivityPolicy::configure(std::span<const BlueprintSpawn> spawns,
                                        std::span<const std::uint16_t> phaseSizes,
                                        std::uint64_t objectiveCounterId,
                                        std::uint32_t bubble) noexcept {
    spawnCount_ = spawns.size() < kMaxSpawns ? spawns.size() : kMaxSpawns;
    for (std::size_t i = 0; i < spawnCount_; ++i) {
        spawns_[i] = spawns[i];
    }
    objectiveCounterId_ = objectiveCounterId != 0 ? objectiveCounterId : 1;
    bubble_ = bubble != 0 ? bubble : 1;

    // Build phase boundaries; unspecified layout becomes a single phase of everything.
    phaseCount_ = 0;
    std::size_t cursor = 0;
    for (std::uint16_t size : phaseSizes) {
        if (phaseCount_ >= kMaxPhases || cursor >= spawnCount_) {
            break;
        }
        const std::size_t remaining = spawnCount_ - cursor;
        const std::uint16_t take =
            static_cast<std::uint16_t>(size < remaining ? size : remaining);
        if (take == 0) {
            continue;
        }
        phaseStart_[phaseCount_] = static_cast<std::uint16_t>(cursor);
        phaseSize_[phaseCount_] = take;
        cursor += take;
        ++phaseCount_;
    }
    if (phaseCount_ == 0 && spawnCount_ > 0) {
        phaseStart_[0] = 0;
        phaseSize_[0] = static_cast<std::uint16_t>(spawnCount_);
        phaseCount_ = 1;
    }
}

void BlueprintActivityPolicy::configure_test(std::uint64_t contentBuild,
                                             std::uint32_t bubble) noexcept {
    // Real Homecoming (mission_towerfall) beat sequence, recovered from a live client memory dump:
    // six encounter zones in mission order, each spawning a four-Cabal Red Legion squad at the zone's
    // real world coordinates. No combat profile is set (the host rejects an unbound combatant); the
    // actors are logical, which is what this live test exercises.
    constexpr std::size_t kZoneCount = 6;
    constexpr std::uint16_t kSquadSize = 4;
    const float zoneX[kZoneCount] = {-493.9F, -458.4F, -548.4F, -519.6F, -654.1F, -723.2F};
    const float zoneY[kZoneCount] = {87.9F, 89.3F, -30.5F, 75.2F, 46.2F, 46.3F};
    // Zones in order: Cabal Landing, Plaza Deck, Shield Line, Ghaul Arrival, Psion Phase-In, Escape.
    const float memberX[kSquadSize] = {-3.0F, 3.0F, -3.0F, 3.0F};
    const float memberY[kSquadSize] = {-3.0F, -3.0F, 3.0F, 3.0F};
    BlueprintSpawn spawns[kZoneCount * kSquadSize];
    std::uint16_t phaseSizes[kZoneCount];
    std::size_t cursor = 0;
    for (std::size_t z = 0; z < kZoneCount; ++z) {
        for (std::size_t m = 0; m < kSquadSize; ++m) {
            spawns[cursor++] = BlueprintSpawn{
                world::Transform{
                    world::Vector3{zoneX[z] + memberX[m], zoneY[z] + memberY[m], 1.0F}, {}},
                {}};
        }
        phaseSizes[z] = kSquadSize;
    }
    configure(std::span<const BlueprintSpawn>(spawns, kZoneCount * kSquadSize),
              std::span<const std::uint16_t>(phaseSizes, kZoneCount),
              /*objectiveCounterId=*/1, bubble);
    // The host creates objective counters through its own API (create_objective), not a policy
    // command, so the test wave cannot bring one into being; a set/add on a missing counter fails
    // the tick. Zero disables the objective commands, leaving spawns and the trigger, which is what
    // this diagnostic exercises in the live host.
    objectiveCounterId_ = 0;
    contentBuild_ = contentBuild;
}

world::PolicyCommandMeta BlueprintActivityPolicy::next_meta(world::TickId executeTick) noexcept {
    world::PolicyCommandMeta meta{};
    meta.definition = kPolicyBlueprint;
    meta.commandId = nextCommandId_++;
    meta.executeTick = executeTick;
    meta.policyOwnerId = kPolicyOwner;
    return meta;
}

void BlueprintActivityPolicy::spawn_phase(std::size_t phase, world::TickId executeTick,
                                          world::HostCommands& commands) noexcept {
    if (phase >= phaseCount_) {
        return;
    }
    const std::size_t begin = phaseStart_[phase];
    const std::size_t end = begin + phaseSize_[phase];
    for (std::size_t i = begin; i < end && i < spawnCount_; ++i) {
        const world::ActorKey actor{static_cast<world::ActorId>(i + 1), world::kFirstGeneration};
        spawnedActors_[i] = actor;

        world::SpawnActorCommand spawn{};
        spawn.actor = actor;
        spawn.transform = spawns_[i].transform;
        spawn.bubble = bubble_;
        spawn.initialAuthorityGeneration = world::kFirstGeneration;
        spawn.authorityMode = world::MotionAuthorityMode::host;
        static_cast<void>(commands.spawn_actor(next_meta(executeTick), spawn));

        if (world::valid_blueprint(spawns_[i].combatProfile)) {
            world::ConfigureCombatCommand combat{};
            combat.actor = actor;
            combat.combatProfile = spawns_[i].combatProfile;
            static_cast<void>(commands.configure_combat(next_meta(executeTick), combat));
        }
    }
}

bool BlueprintActivityPolicy::in_current_phase(const world::ActorKey& actor) const noexcept {
    if (currentPhase_ >= phaseCount_) {
        return false;
    }
    const std::size_t begin = phaseStart_[currentPhase_];
    const std::size_t end = begin + phaseSize_[currentPhase_];
    for (std::size_t i = begin; i < end && i < spawnCount_; ++i) {
        if (world::equal_actor(actor, spawnedActors_[i])) {
            return true;
        }
    }
    return false;
}

world::ActivityPolicyManifest
BlueprintActivityPolicy::manifest_for(std::uint64_t contentBuild) noexcept {
    world::ActivityPolicyManifest manifest{};
    manifest.policy = kPolicyBlueprint;
    manifest.contentBuildId = contentBuild;
    manifest.allowedCommandMask =
        world::command_kind_mask(world::HostCommandKind::spawnActor)
        | world::command_kind_mask(world::HostCommandKind::configureCombat)
        | world::command_kind_mask(world::HostCommandKind::createTrigger)
        | world::command_kind_mask(world::HostCommandKind::setObjectiveCounter);
    manifest.fixedRateHz = world::kDefaultFixedRateHz;
    manifest.actorBudget = static_cast<std::uint32_t>(kMaxSpawns);
    manifest.triggerBudget = 2;
    manifest.queryBudget = 0;
    manifest.counterBudget = 2;
    manifest.creditBudget = 0;
    manifest.persistenceSchemaVersion = 1;
    return manifest;
}

world::ActivityPolicyManifest BlueprintActivityPolicy::manifest() const noexcept {
    return manifest_for(contentBuild_);
}

bool BlueprintActivityPolicy::initialize(const world::ActivityPolicyContext& context,
                                         world::HostCommands& commands) noexcept {
    static_cast<void>(context);
    currentPhase_ = 0;
    objectiveComplete_ = phaseCount_ == 0;

    if (phaseCount_ > 0) {
        spawn_phase(0, kFirstExecuteTick, commands);
        aliveInPhase_ = phaseSize_[0];

        world::CreateTriggerCommand trigger{};
        trigger.triggerId = kTriggerId;
        trigger.transform = spawns_[0].transform;
        trigger.halfExtents = world::Vector3{1000.0F, 1000.0F, 1000.0F};
        trigger.triggerProfile = kPolicyBlueprint;
        static_cast<void>(commands.create_trigger(next_meta(kFirstExecuteTick), trigger));

        if (objectiveCounterId_ != 0) {
            world::SetObjectiveCounterCommand objective{};
            objective.counterId = objectiveCounterId_;
            objective.value = static_cast<std::int64_t>(aliveInPhase_);
            objective.expectedRevision = 0;
            static_cast<void>(
                commands.set_objective_counter(next_meta(kFirstExecuteTick), objective));
        }
    }
    return true;
}

void BlueprintActivityPolicy::pre_tick(const world::PolicyTickContext& context,
                                       world::HostCommands& commands) noexcept {
    static_cast<void>(context);
    static_cast<void>(commands);
}

void BlueprintActivityPolicy::post_tick(const world::PolicyTickContext& context,
                                        std::span<const world::CommittedEvent> committedEvents,
                                        world::HostCommands& commands) noexcept {
    for (const world::CommittedEvent& event : committedEvents) {
        if (event.kind == world::CommittedEventKind::actorRemoved && in_current_phase(event.actor)
            && aliveInPhase_ > 0) {
            --aliveInPhase_;
        }
    }

    if (aliveInPhase_ != 0 || objectiveComplete_) {
        return;
    }

    if (currentPhase_ + 1 < phaseCount_) {
        ++currentPhase_;
        spawn_phase(currentPhase_, context.tick + 1, commands);
        aliveInPhase_ = phaseSize_[currentPhase_];
    } else {
        objectiveComplete_ = true;
        aliveInPhase_ = 0;
    }

    if (objectiveCounterId_ != 0) {
        world::SetObjectiveCounterCommand objective{};
        objective.counterId = objectiveCounterId_;
        objective.value = static_cast<std::int64_t>(aliveInPhase_);
        objective.expectedRevision = 0;
        static_cast<void>(commands.set_objective_counter(next_meta(context.tick + 1), objective));
    }
}

bool BlueprintActivityPolicy::save(world::IPolicyStateWriter& writer) const noexcept {
    const PersistState state{aliveInPhase_, nextCommandId_,
                             static_cast<std::uint32_t>(currentPhase_),
                             static_cast<std::uint8_t>(objectiveComplete_ ? 1 : 0)};
    std::array<std::byte, sizeof(PersistState)> bytes{};
    std::memcpy(bytes.data(), &state, sizeof(PersistState));
    return writer.write(bytes);
}

bool BlueprintActivityPolicy::load(world::IPolicyStateReader& reader) noexcept {
    std::array<std::byte, sizeof(PersistState)> bytes{};
    if (!reader.read(bytes)) {
        return false;
    }
    PersistState state{};
    std::memcpy(&state, bytes.data(), sizeof(PersistState));
    aliveInPhase_ = state.aliveInPhase;
    nextCommandId_ = state.nextCommandId;
    currentPhase_ = state.currentPhase;
    objectiveComplete_ = state.objectiveComplete != 0;
    return true;
}

world::ActorKey BlueprintActivityPolicy::spawned_actor(std::size_t index) const noexcept {
    return index < spawnCount_ ? spawnedActors_[index] : world::ActorKey{};
}

} // namespace sunrise::server::gameplay::encounter
