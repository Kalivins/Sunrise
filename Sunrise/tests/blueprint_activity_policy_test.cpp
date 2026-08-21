// Deterministic, headless integration test for the encounter-engine vertical slice.
//
// It drives a real WorldRunner with a BlueprintActivityPolicy and a stub executor (no client, no
// wire, no wall-clock). It proves the policy spawns a wave at its blueprint transforms and advances
// its objective to complete as those actors are removed — the core encounter loop, running entirely
// inside the deterministic logical world.
//
// Builds standalone via Sunrise/tests/CMakeLists.txt; run the resulting executable (exit 0 == pass).
// Verified only on the fork CI toolchain (the project does not build locally).

#include <cstdio>

#include "server/gameplay/encounter/blueprint_activity_policy.h"
#include "server/gameplay/physics/world/host_command.h"
#include "server/gameplay/physics/world/host_command_executor.h"
#include "server/gameplay/physics/world/world_runner.h"
#include "server/gameplay/physics/world/world_types.h"

namespace world = sunrise::server::gameplay::physics::world;
namespace enc = sunrise::server::gameplay::encounter;

namespace {

int g_failures = 0;

void check(bool condition, const char* label) {
    std::printf("[%s] %s\n", condition ? "PASS" : "FAIL", label);
    if (!condition) {
        ++g_failures;
    }
}

/** Accepts every non-core service command without side effects; core actor commands go elsewhere. */
class StubExecutor final : public world::IHostCommandExecutor {
public:
    world::HostCommandExecutionResult
    execute_command(const world::HostExecutionContext&, const world::HostCommand&,
                    std::span<const world::ActorSnapshot>,
                    std::span<world::CommittedEvent>) noexcept override {
        world::HostCommandExecutionResult result{};
        result.eventCount = 0;
        result.rejectReason = world::CommandRejectReason::none;
        result.status = world::HostCommandExecutionStatus::applied;
        return result;
    }

    world::HostTickExecutionResult
    step_services(const world::HostExecutionContext&, std::span<const world::ActorSnapshot>,
                  std::span<const world::CommittedEvent>,
                  std::span<world::CommittedEvent>) noexcept override {
        world::HostTickExecutionResult result{};
        result.eventCount = 0;
        result.healthy = true;
        return result;
    }
};

/** Builds a valid host-sourced command that removes one logical actor next tick. */
world::HostCommand make_remove(const world::WorldRunner& runner, world::ActorKey actor,
                               std::uint64_t sequence) {
    world::HostCommand command{};
    command.header.world = runner.identity();
    command.header.definition = world::BlueprintRef{0x7E57C0DEU, 1U};
    command.header.source = world::CommandSource{0x7E57U, world::CommandSourceKind::host};
    command.header.commandId = sequence;
    command.header.executeTick = runner.tick() + 1;
    command.header.policyOwnerId = 0x7E57U;
    command.header.sourceSequence = sequence;
    command.payload = world::RemoveActorCommand{actor};
    return command;
}

} // namespace

int main() {
    // A three-combatant wave at distinct blueprint transforms (Homecoming sq_deck_* style positions).
    const world::BlueprintRef cabal{0xCABA1001U, 1U};
    const enc::BlueprintSpawn spawns[] = {
        {world::Transform{world::Vector3{73.5F, -431.0F, 1.0F}, {}}, cabal},
        {world::Transform{world::Vector3{80.2F, -457.3F, 1.0F}, {}}, cabal},
        {world::Transform{world::Vector3{65.9F, -478.4F, 1.0F}, {}}, cabal},
    };

    enc::BlueprintActivityPolicy policy;
    policy.configure(std::span<const enc::BlueprintSpawn>(spawns), /*objectiveCounterId=*/42,
                     /*bubble=*/1);

    StubExecutor executor;
    world::WorldOpenConfig config{};
    config.executor = &executor;
    config.activitySessionId = 0xA0A0U;
    config.ownerGeneration = 1;
    config.deterministicSeed = 1;
    config.allowHostActorCommands = true;

    world::WorldRunner runner;
    check(runner.open(config, &policy), "world opens with the blueprint policy");

    // Tick 1 drains the initialize spawns -> the wave exists in the logical world.
    const world::AdvanceResult spawnTick = runner.advance(1);
    check(spawnTick.healthy, "spawn tick is healthy");
    check(runner.actor_count() == 3, "three actors spawned from the blueprint");
    check(policy.wave_size() == 3, "policy reports the wave size");
    check(policy.alive_count() == 3, "policy tracks three alive");
    check(!policy.objective_complete(), "objective not complete while the wave lives");

    // Remove each spawned actor; the policy watches actorRemoved and clears its objective.
    for (std::size_t i = 0; i < policy.wave_size(); ++i) {
        const world::CommandSubmitStatus status =
            runner.submit(make_remove(runner, policy.spawned_actor(i),
                                      static_cast<std::uint64_t>(100 + i)));
        check(status == world::CommandSubmitStatus::accepted, "remove command accepted");
    }

    const world::AdvanceResult clearTick = runner.advance(1);
    check(clearTick.healthy, "clear tick is healthy");
    check(runner.actor_count() == 0, "all actors removed");
    check(policy.alive_count() == 0, "policy tracks zero alive");
    check(policy.objective_complete(), "objective complete once the wave is clear");

    std::printf("\n%s (%d failure(s))\n", g_failures == 0 ? "ALL PASSED" : "FAILURES", g_failures);
    return g_failures == 0 ? 0 : 1;
}
