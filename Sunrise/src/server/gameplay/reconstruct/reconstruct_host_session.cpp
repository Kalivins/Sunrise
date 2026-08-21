#include "reconstruct_host_session.h"

#include <cstddef>
#include <cstdint>

#include "../../../core/settings/settings.h"
#include "../../../state/activity/destination/definition.h"
#include "../../../state/activity/forced/activity_forced_destination.h"
#include "../../../state/activity/runtime.h"
#include "../gameplay_log.h"
#include "../group/group_host_sessions.h"

namespace sunrise::server::gameplay::reconstruct {
namespace {

namespace forced = state::activity::forced;
namespace destination = state::activity::destination;

/** One synthetic group-session key for the reconstructed row. Nonzero and stable across ticks. */
constexpr std::uint64_t kReconstructGroupSession = 0x5211000000000001ULL;

/**
 * A claimable region index for the reconstructed row. The only host-table constraint is that it is
 * not the unknown-region sentinel. It is NOT a real region and NOT a slice-set index; aligning it
 * with a true region is an R5 concern, so it is named to stop a later reader assuming otherwise.
 */
constexpr std::int32_t kSyntheticRegion = 64;

/** Source activity-session record this rung committed, or absent when it holds none. */
std::uint64_t g_sourceId = state::activity::kAbsentSessionId;
/** Retained host-row generation, or zero when none is held. */
std::uint64_t g_generation = 0;
/** Region the current source and host row were claimed for. */
std::int32_t g_regionIndex = -1;
/** Last host state and readiness logged, so the witness line prints once per change, not per tick. */
int g_lastLoggedState = -1;
bool g_lastReady = false;

/** @return The name of one host-session state, so a stuck rung reads apart from a silent one. */
[[nodiscard]] const char* host_state_name(group::HostSessionState value) noexcept {
    switch (value) {
    case group::HostSessionState::absent:
        return "absent";
    case group::HostSessionState::pending:
        return "pending";
    case group::HostSessionState::ready:
        return "ready";
    case group::HostSessionState::conflict:
        return "conflict";
    case group::HostSessionState::full:
        return "full";
    }
    return "unknown";
}

/** Releases the source record and the retained host generation this rung owns. */
void teardown() noexcept {
    // reset_host_sessions clears the table synchronously: it frees each row's allocated target and
    // drops its source retain in one pass. release_host_session alone would only drop the retain,
    // leaving the row live for one more tick (it retires inside the next allocate pass) with a host
    // row still referencing a source we are about to free. Clearing first closes that window.
    group::reset_host_sessions();
    if (g_sourceId != state::activity::kAbsentSessionId) {
        static_cast<void>(state::activity::release_session(g_sourceId));
        g_sourceId = state::activity::kAbsentSessionId;
    }
    g_generation = 0;
    g_regionIndex = -1;
    g_lastLoggedState = -1;
    g_lastReady = false;
}

/**
 * Commits one source activity-session record for the forced destination.
 * Builds the selection through forced::apply, the exact path the roster uses, so the source
 * record's destination is identical to the rostered one rather than a hand-rolled near-copy that
 * binding_matches would still accept while everything downstream diverged in silence.
 */
[[nodiscard]] bool commit_source(std::int32_t regionIndex) noexcept {
    destination::DestinationSelection selection{};
    if (!forced::apply(selection)) {
        report(core::log::Level::warn, "ev=gameplay stage=reconstruct result=fail reason=override");
        return false;
    }
    std::uint64_t sessionId = state::activity::kAbsentSessionId;
    state::activity::PendingAllocation allocation{};
    if (!state::activity::prepare_session(selection, sessionId, allocation)) {
        report(core::log::Level::warn, "ev=gameplay stage=reconstruct result=fail reason=prepare");
        return false;
    }
    if (!state::activity::commit(allocation)) {
        report(core::log::Level::warn, "ev=gameplay stage=reconstruct result=fail reason=commit");
        return false;
    }
    g_sourceId = sessionId;
    g_regionIndex = regionIndex;
    return true;
}

} // namespace

void reconstruct_service() noexcept {
    const bool want = core::settings::get().server.activation.reconstructHostSession
                      && forced::override_active();
    if (!want) {
        if (g_sourceId != state::activity::kAbsentSessionId || g_generation != 0) {
            teardown();
        }
        return;
    }

    if (g_sourceId == state::activity::kAbsentSessionId && !commit_source(kSyntheticRegion)) {
        return;  // commit_source logged the exact failing step (override, prepare, or commit).
    }

    state::activity::SessionBinding source{};
    if (!state::activity::snapshot_binding(g_sourceId, source)) {
        report(core::log::Level::warn, "ev=gameplay stage=reconstruct result=fail reason=binding");
        return;
    }

    // Idempotent: a matching group-session id returns the existing row rather than a new one.
    group::HostSessionBinding pending{};
    const group::HostSessionState hostState =
        group::request_host_session(kReconstructGroupSession, source, kSyntheticRegion, pending);
    if (hostState == group::HostSessionState::pending && g_generation == 0
        && pending.generation != 0) {
        // Retain the generation so the pump's LRU cannot evict it before it allocates its target.
        if (group::retain_host_session(pending.generation)) {
            g_generation = pending.generation;
        }
    }

    // Witness: allocate_claimed_host_sessions runs after this in the same service pass, so the row
    // is still pending the tick it is first claimed and reads ready from the next tick onward.
    group::HostSessionBinding ready{};
    group::HostSessionBinding check{};
    const bool hostReady = group::host_session_for_group(kReconstructGroupSession, ready)
                           && group::host_session_for_activity(ready.target.sessionId, check);
    // Carry the exact host state every time: absent/pending/conflict/full all fail into "waiting"
    // and must read apart, or a stuck rung looks like one silent symptom. Log once per change.
    if (static_cast<int>(hostState) != g_lastLoggedState || hostReady != g_lastReady) {
        report(core::log::Level::info,
               "ev=gameplay stage=reconstruct result=%s host_state=%s source=0x%llX target=0x%llX "
               "region=%d",
               hostReady ? "hostsession" : "waiting",
               host_state_name(hostState),
               static_cast<unsigned long long>(g_sourceId),
               static_cast<unsigned long long>(ready.target.sessionId),
               g_regionIndex);
        g_lastLoggedState = static_cast<int>(hostState);
        g_lastReady = hostReady;
    }
}

} // namespace sunrise::server::gameplay::reconstruct
