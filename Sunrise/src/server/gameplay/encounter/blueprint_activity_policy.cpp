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
                                        std::uint64_t objectiveCounterId,
                                        std::uint32_t bubble) noexcept {
    spawnCount_ = spawns.size() < kMaxSpawns ? spawns.size() : kMaxSpawns;
    for (std::size_t i = 0; i < spawnCount_; ++i) {
        spawns_[i] = spawns[i];
    }
    objectiveCounterId_ = objectiveCounterId != 0 ? objectiveCounterId : 1;
    bubble_ = bubble != 0 ? bubble : 1;
}

world::PolicyCommandMeta BlueprintActivityPolicy::next_meta(world::TickId executeTick) noexcept {
    world::PolicyCommandMeta meta{};
    meta.definition = kPolicyBlueprint;
    meta.commandId = nextCommandId_++;
    meta.executeTick = executeTick;
    meta.policyOwnerId = kPolicyOwner;
    return meta;
}

world::ActivityPolicyManifest BlueprintActivityPolicy::manifest() const noexcept {
    world::ActivityPolicyManifest manifest{};
    manifest.policy = kPolicyBlueprint;
    manifest.contentBuildId = 0;
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

bool BlueprintActivityPolicy::initialize(const world::ActivityPolicyContext& context,
                                         world::HostCommands& commands) noexcept {
    static_cast<void>(context);

    for (std::size_t i = 0; i < spawnCount_; ++i) {
        const world::ActorKey actor{static_cast<world::ActorId>(i + 1), world::kFirstGeneration};
        spawnedActors_[i] = actor;

        world::SpawnActorCommand spawn{};
        spawn.actor = actor;
        spawn.transform = spawns_[i].transform;
        spawn.bubble = bubble_;
        spawn.initialAuthorityGeneration = world::kFirstGeneration;
        spawn.authorityMode = world::MotionAuthorityMode::host;
        if (!ok(commands.spawn_actor(next_meta(kFirstExecuteTick), spawn))) {
            return false;
        }

        if (world::valid_blueprint(spawns_[i].combatProfile)) {
            world::ConfigureCombatCommand combat{};
            combat.actor = actor;
            combat.combatProfile = spawns_[i].combatProfile;
            static_cast<void>(commands.configure_combat(next_meta(kFirstExecuteTick), combat));
        }
    }

    if (spawnCount_ > 0) {
        world::CreateTriggerCommand trigger{};
        trigger.triggerId = kTriggerId;
        trigger.transform = spawns_[0].transform;
        trigger.halfExtents = world::Vector3{1000.0F, 1000.0F, 1000.0F};
        trigger.triggerProfile = kPolicyBlueprint;
        static_cast<void>(commands.create_trigger(next_meta(kFirstExecuteTick), trigger));

        world::SetObjectiveCounterCommand objective{};
        objective.counterId = objectiveCounterId_;
        objective.value = static_cast<std::int64_t>(spawnCount_);
        objective.expectedRevision = 0;
        static_cast<void>(commands.set_objective_counter(next_meta(kFirstExecuteTick), objective));
    }

    aliveCount_ = spawnCount_;
    objectiveComplete_ = spawnCount_ == 0;
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
        if (event.kind != world::CommittedEventKind::actorRemoved) {
            continue;
        }
        for (std::size_t i = 0; i < spawnCount_; ++i) {
            if (world::equal_actor(event.actor, spawnedActors_[i]) && aliveCount_ > 0) {
                --aliveCount_;
                break;
            }
        }
    }

    if (aliveCount_ == 0 && !objectiveComplete_ && spawnCount_ > 0) {
        objectiveComplete_ = true;
        world::SetObjectiveCounterCommand objective{};
        objective.counterId = objectiveCounterId_;
        objective.value = 0;
        objective.expectedRevision = 0;
        static_cast<void>(commands.set_objective_counter(next_meta(context.tick + 1), objective));
    }
}

bool BlueprintActivityPolicy::save(world::IPolicyStateWriter& writer) const noexcept {
    const PersistState state{aliveCount_, nextCommandId_,
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
    aliveCount_ = state.aliveCount;
    nextCommandId_ = state.nextCommandId;
    objectiveComplete_ = state.objectiveComplete != 0;
    return true;
}

world::ActorKey BlueprintActivityPolicy::spawned_actor(std::size_t index) const noexcept {
    return index < spawnCount_ ? spawnedActors_[index] : world::ActorKey{};
}

} // namespace sunrise::server::gameplay::encounter
