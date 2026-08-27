#include "physics_session.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <memory>
#include <new>
#include <span>
#include <string>

#include "../../../../core/settings/settings.h"
#include "../../../../middleware/gameplay/external/common_state.h"
#include "../../../../state/activity/entity_slots/runtime.h"
#include "../../../../state/gameplay/physics/runtime.h"
#include "../common/common_sync.h"
#include "../../gameplay_log.h"
#include "../../group/group_host.h"
#include "../../group/group_host_sessions.h"
#include "../../peer/external_frame_stage.h"
#include "../../peer/peer_transport.h"
#include "../replication/world_coordinator.h"
#include "bubble_host.h"
#include "runtime.h"

namespace sunrise::server::gameplay::physics::host::session {
namespace {

namespace replica = state::gameplay::physics;

/**
 * Drives one freshly bound common state to Phase::confirmed with a synthetic, binding-matching common
 * root, so the encode probe can pass prepare_frame's common-ready gate. The real handshake
 * (common::observe fed by inbound patch-epoch / type-52 traffic) has no caller yet; this substitutes
 * it locally. Nothing is transmitted, so the fabricated root never reaches the client -- it only lets
 * a squad frame BUILD and ENCODE. Acts only on an awaitingObservation state; a confirmed one is left
 * alone, so it is idempotent across ticks and a real bind resets it for the next drive.
 * @return True when the state is confirmed (already, or after this drive).
 */
[[nodiscard]] bool probe_confirm_common(common::State& state) noexcept {
    if (common::ready(state)) {
        return true;
    }
    if (state.phase != common::Phase::awaitingObservation
        || state.binding.activitySessionId == 0) {
        return false;
    }
    middleware::gameplay::external::CommonState root{};
    root.patchEpoch = state.binding.patchEpoch;
    root.entries[0].activitySessionId = state.binding.activitySessionId;
    root.entries[0].reconciliationGeneration = 0;
    root.entryCount = 1;
    if (common::observe(state, root) != common::ObserveResult::initial) {
        return false;
    }
    common::AdvancePlan plan{};
    if (!common::prepare_advance(state, plan) || !common::commit_advance(state, plan)) {
        return false;
    }
    root.entries[0].reconciliationGeneration = plan.nextGeneration;
    static_cast<void>(common::observe(state, root));
    return common::ready(state);
}

/** Worlds this bridge holds open. The host bounds its own table at the same number. */
constexpr std::size_t kSessionCapacity = kWorldCapacity;
/** Admitted rows one snapshot reads. The group table holds no more than this. */
constexpr std::size_t kAdmittedCapacity = 8;
/** Host-session rows one snapshot reads. */
constexpr std::size_t kHostRowCapacity = 8;
/** The world runs at 30 Hz, so one tick is due every 33 ms. */
constexpr std::uint64_t kTickIntervalMs = 33;
/** Empty scene scale. Nothing reads it until an actor carries a transform. */
constexpr float kMillimetersPerUnit = 1000.0F;
/**
 * Content build stamped on the scene, its manifest and its navigation scene.
 * The backend refuses a zero one. This scene loads no content, so the number's only job is to make
 * those three agree; it becomes a real build id once a scene carries geometry.
 * TODO: no reader outside that agreement check. Take it from `state::build_data::BuildIdentity`
 * when a scene loads content.
 */
constexpr std::uint64_t kSceneContentBuild = 1;
/**
 * Worker wake interval. `tick_bound` paces the 30 Hz step itself, so this only bounds the jitter.
 * A world tick is never due more than this long after its deadline.
 */
constexpr std::uint64_t kWorkerSliceMs = 8;
/**
 * How often the worker rebuilds the bound set from the admitted peers.
 * Every wake would take three shared locks a hundred times a second to notice a join that takes
 * seconds to arrive.
 */
constexpr std::uint64_t kReconcileIntervalMs = 250;
/** A refused open waits this long before it is tried again. */
constexpr std::uint64_t kOpenRetryMs = 5'000;
/** Attempts one host generation gets before the bridge stops trying it. */
constexpr std::uint32_t kOpenAttemptLimit = 3;

/** One admitted group session bound to one open world. */
struct Bound final {
    WorldHandle world{};
    HostPeerHandle peer{};
    replica::ContextHandle context{};
    replica::PeerReplicaHandle replicaHandle{};
    std::uint64_t groupSessionId{};
    std::uint64_t activitySessionId{};
    std::uint64_t hostGeneration{};
    std::uint64_t nextTick{};
    std::uint64_t ticks{};
    bool occupied{};
    // Dev diagnostic only: a world force-opened by the encounter test hook with no peer bound. The
    // reconcile pass leaves it alone so the blueprint policy keeps ticking without a live roster.
    bool testForced{};
};

/**
 * One host generation this bridge failed to open a world for.
 * Without this the retry runs every service slice. That is what it did: 12,156 refused opens in
 * one run, each one initializing and clearing the whole physics backend, until the game's main
 * loop stalled.
 */
struct Attempt final {
    std::uint64_t groupSessionId{};
    std::uint64_t hostGeneration{};
    std::uint64_t nextAttempt{};
    std::uint32_t failures{};
    bool occupied{};
};

/** The coordinators are large, so the whole table is one heap allocation made on first use. */
struct Storage final {
    std::array<Bound, kSessionCapacity> bound{};
    std::array<Attempt, kAdmittedCapacity> attempts{};
    std::array<replication::WorldCoordinator, kSessionCapacity> coordinators{};
};

std::unique_ptr<Storage> g_storage{};
/** The worker, or null while the bridge is off. Only the pump thread writes these two. */
HANDLE g_thread{};
/** Manual-reset stop signal. It doubles as the worker's sleep, so a stop is never waited out. */
HANDLE g_stop{};
/**
 * Separates one bind of a group session from the next.
 * State refuses a zero view epoch and uses these fields only to fail a stale handle closed, so a
 * process-local counter is the whole requirement. It is not a wire value.
 */
std::uint64_t g_bindEpoch = 0;

/** @return The table, allocated on first use, or null when it cannot be allocated. */
[[nodiscard]] Storage* storage() noexcept {
    if (g_storage == nullptr) {
        g_storage.reset(new (std::nothrow) Storage{});
    }
    return g_storage.get();
}

/**
 * Finds the host row that published one admitted group session.
 * @param rows Copied host-session rows.
 * @param count Rows copied.
 * @param groupSessionId Group session the peer joined.
 * @return The row, or null when no host row published it.
 */
[[nodiscard]] const group::HostSessionRow*
find_host_row(const std::array<group::HostSessionRow, kHostRowCapacity>& rows,
              std::size_t count,
              std::uint64_t groupSessionId) noexcept {
    for (std::size_t index = 0; index < count; ++index) {
        if (rows[index].groupSessionId == groupSessionId) {
            return &rows[index];
        }
    }
    return nullptr;
}

/** @return True when one group session is still admitted and its join has finished. */
[[nodiscard]] bool still_joined(const std::array<group::AdmittedRow, kAdmittedCapacity>& rows,
                                std::size_t count,
                                std::uint64_t groupSessionId) noexcept {
    for (std::size_t index = 0; index < count; ++index) {
        if (rows[index].sessionId == groupSessionId && rows[index].joinComplete) {
            return true;
        }
    }
    return false;
}

/**
 * Finds or claims the attempt record for one host generation.
 * A different generation is a different activity, so its record starts clean.
 * @param table Bridge table.
 * @param groupSessionId Group session being opened.
 * @param hostGeneration Host-row generation being opened.
 * @return The record, or null when the table is full.
 */
[[nodiscard]] Attempt*
attempt_for(Storage& table, std::uint64_t groupSessionId, std::uint64_t hostGeneration) noexcept {
    Attempt* free = nullptr;
    for (Attempt& record : table.attempts) {
        if (record.occupied && record.groupSessionId == groupSessionId) {
            if (record.hostGeneration != hostGeneration) {
                record = {groupSessionId, hostGeneration, 0, 0, true};
            }
            return &record;
        }
        if (free == nullptr && !record.occupied) {
            free = &record;
        }
    }
    if (free != nullptr) {
        *free = {groupSessionId, hostGeneration, 0, 0, true};
    }
    return free;
}

/** Forgets the attempt record for one group session, so a later bind starts clean. */
void clear_attempt(Storage& table, std::uint64_t groupSessionId) noexcept {
    for (Attempt& record : table.attempts) {
        if (record.occupied && record.groupSessionId == groupSessionId) {
            record = {};
        }
    }
}

/** @return The slot already bound to one group session, or the capacity when none is. */
[[nodiscard]] std::size_t find_bound(const Storage& table, std::uint64_t groupSessionId) noexcept {
    for (std::size_t index = 0; index < table.bound.size(); ++index) {
        if (table.bound[index].occupied && table.bound[index].groupSessionId == groupSessionId) {
            return index;
        }
    }
    return table.bound.size();
}

/** Releases every owner one bound slot holds, in reverse order, then clears it. */
void close_bound(Storage& table, std::size_t slot) noexcept {
    Bound& entry = table.bound[slot];
    BubbleHost* host = runtime::instance();
    // The planner belongs to the host peer, so the coordinator has to let it go before the peer
    // does. Borrowing it after unbind_peer would name a retired slot.
    PeerServiceAccess services{};
    if (host != nullptr
        && host->peer_services(entry.world, entry.peer, services) == HostStatus::success
        && services.replication != nullptr) {
        static_cast<void>(table.coordinators[slot].unregister_peer(*services.replication));
    }
    if (host != nullptr) {
        static_cast<void>(host->unbind_peer(entry.world, entry.peer));
        static_cast<void>(host->close_world(entry.world));
    }
    static_cast<void>(replica::retire_peer_replica(entry.replicaHandle));
    static_cast<void>(replica::reset_context(entry.context));
    report(core::log::Level::info,
           "ev=physics stage=world result=closed session=0x%016llX activity=0x%016llX ticks=%llu",
           static_cast<unsigned long long>(entry.groupSessionId),
           static_cast<unsigned long long>(entry.activitySessionId),
           static_cast<unsigned long long>(entry.ticks));
    entry = {};
}

/**
 * Publishes one State replica context for an activity that already committed its lease.
 * @param row Host row naming the activity session.
 * @param handle Receives the context handle on success.
 * @return True when both lease masks were read and the context published.
 */
[[nodiscard]] bool publish_context(const group::HostSessionRow& row,
                                   replica::ContextHandle& handle) noexcept {
    replica::ActivityReplicaContext context{};
    if (!state::activity::entity_slots::lease_masks(
            row.hostSessionId, context.clientLeaseMask, context.serverReserveMask)) {
        return false;
    }
    context.activitySessionId = row.hostSessionId;
    context.currentBubble = static_cast<std::uint32_t>(row.regionIndex);
    // Every session reaching this bridge joined a published public host row.
    context.role = replica::ReplicaRole::publicTarget;
    // The patch epoch stays zero here and in the common binding below, so the two agree and State
    // accepts them. Only frame encoding compares it against the client's own root, and nothing
    // encodes a frame yet.
    return replica::publish_context(context, handle);
}

/**
 * Opens one world, binds its peer, and registers both with the coordinator.
 * @param table Bridge table.
 * @param slot Free bridge slot.
 * @param admitted Admitted row for the peer.
 * @param row Host row naming the activity session.
 * @param now Monotonic tick count in milliseconds.
 * @return True when the world opened. False is a refusal the caller must back off from.
 */
[[nodiscard]] bool open_bound(Storage& table,
                              std::size_t slot,
                              const group::AdmittedRow& admitted,
                              const group::HostSessionRow& row,
                              std::uint64_t now) noexcept {
    BubbleHost* host = runtime::instance();
    if (host == nullptr) {
        return false;
    }
    peer::LinkIdentity link{};
    if (admitted.joinId == 0 || row.generation == 0 || row.hostSessionId == 0
        || !peer::link_identity(admitted.sessionId, link)) {
        return false;
    }
    Bound entry{};
    if (!publish_context(row, entry.context)) {
        // The lease commits after the join, so this is ordinary for the first slices.
        return false;
    }
    ++g_bindEpoch;
    replica::ViewKey view{};
    view.peer.authenticatedMemberId = admitted.joinId;
    view.peer.associationEpoch = row.generation;
    view.peer.remoteConnectionSequence = link.remoteConnectionSequence;
    view.peer.localConnectionSequence = link.localConnectionSequence;
    view.peer.channelEpoch = g_bindEpoch;
    view.groupSessionId = admitted.sessionId;
    view.viewEpoch = g_bindEpoch;
    if (!replica::publish_peer_replica(entry.context, view, entry.replicaHandle)) {
        static_cast<void>(replica::reset_context(entry.context));
        report(core::log::Level::warn,
               "ev=physics stage=world result=fail session=0x%016llX reason=replica",
               static_cast<unsigned long long>(admitted.sessionId));
        return false;
    }

    WorldOpenRequest request{};
    request.scene.stableSceneId = row.hostSessionId;
    request.scene.contentBuild = kSceneContentBuild;
    request.scene.bubble = static_cast<std::uint32_t>(row.regionIndex);
    // A wide provisional box, matching the force-open path, so the mission policy's trigger and
    // static bodies are accepted; the zero box refuses the first body and the tick goes unhealthy.
    // TODO: take the real extents from the destination's scenario layout when an actor carries a
    // transform.
    request.scene.bounds.minimum = {-5000.0F, -5000.0F, -5000.0F};
    request.scene.bounds.maximum = {5000.0F, 5000.0F, 5000.0F};
    request.logicalWorldId = row.hostSessionId;
    request.activitySessionId = row.hostSessionId;
    request.ownerEpoch = row.generation;
    request.deterministicSeed = row.hostSessionId;
    request.millimetersPerUnit = kMillimetersPerUnit;
    // A null policy selects the inert fallback, which spawns nothing and makes no mission choice.
    const HostStatus opened = host->open_world(request, nullptr, entry.world);
    if (opened != HostStatus::success) {
        static_cast<void>(replica::retire_peer_replica(entry.replicaHandle));
        static_cast<void>(replica::reset_context(entry.context));
        report(core::log::Level::warn,
               "ev=physics stage=world result=fail session=0x%016llX status=%u",
               static_cast<unsigned long long>(admitted.sessionId),
               static_cast<unsigned>(opened));
        return false;
    }

    PeerOpenRequest peerRequest{};
    peerRequest.interest.memberId = admitted.joinId;
    peerRequest.interest.viewGeneration = g_bindEpoch;
    peerRequest.interest.activitySessionId = row.hostSessionId;
    peerRequest.common.activitySessionId = row.hostSessionId;
    peerRequest.common.bindingGeneration = row.generation;
    peerRequest.replica = entry.replicaHandle;
    const HostStatus bound = host->bind_peer(entry.world, peerRequest, entry.peer);
    PeerServiceAccess services{};
    // The five post-bind terms are evaluated stepwise so the witness can name the first to fail,
    // instead of collapsing bind / services / replication / coordinator into one "reason=peer".
    const HostStatus servicesStatus = bound == HostStatus::success
                                          ? host->peer_services(entry.world, entry.peer, services)
                                          : HostStatus::staleHandle;
    const bool hasReplication =
        servicesStatus == HostStatus::success && services.replication != nullptr;
    const bool coordinatorBound =
        hasReplication
        && table.coordinators[slot].bind(
            {row.hostSessionId, entry.world.generation, row.generation}, entry.context);
    const bool registered =
        coordinatorBound
        && table.coordinators[slot].register_peer(*services.replication, peerRequest.interest);
    if (!registered) {
        const char* const step = bound != HostStatus::success          ? "bind_peer"
                                 : servicesStatus != HostStatus::success ? "peer_services"
                                 : services.replication == nullptr       ? "no_replication"
                                 : !coordinatorBound                     ? "coordinator_bind"
                                                                         : "register_peer";
        if (bound == HostStatus::success) {
            static_cast<void>(host->unbind_peer(entry.world, entry.peer));
        }
        static_cast<void>(host->close_world(entry.world));
        static_cast<void>(replica::retire_peer_replica(entry.replicaHandle));
        static_cast<void>(replica::reset_context(entry.context));
        report(core::log::Level::warn,
               "ev=physics stage=world result=fail session=0x%016llX bind=%u services=%u reason=peer "
               "step=%s",
               static_cast<unsigned long long>(admitted.sessionId),
               static_cast<unsigned>(bound),
               static_cast<unsigned>(servicesStatus),
               step);
        return false;
    }

    entry.groupSessionId = admitted.sessionId;
    entry.activitySessionId = row.hostSessionId;
    entry.hostGeneration = row.generation;
    entry.nextTick = now;
    entry.occupied = true;
    table.bound[slot] = entry;
    report(core::log::Level::info,
           "ev=physics stage=world result=opened session=0x%016llX activity=0x%016llX region=%d "
           "member=0x%016llX worlds=%zu",
           static_cast<unsigned long long>(admitted.sessionId),
           static_cast<unsigned long long>(row.hostSessionId),
           row.regionIndex,
           static_cast<unsigned long long>(admitted.joinId),
           host->world_count());
    return true;
}

/**
 * Runs every tick one world owes, then reports the result at a bounded rate.
 * @param table Bridge table.
 * @param slot Occupied bridge slot.
 * @param now Monotonic tick count in milliseconds.
 */
void tick_bound(Storage& table, std::size_t slot, std::uint64_t now) noexcept {
    Bound& entry = table.bound[slot];
    BubbleHost* host = runtime::instance();
    if (host == nullptr || now < entry.nextTick) {
        return;
    }
    // One tick per service slice. Catching a backlog up in one pass would run the world faster
    // than its fixed step for as long as the slice was late.
    entry.nextTick = now + kTickIntervalMs;
    const TickResult result = host->tick(entry.world);
    if (result.status != HostStatus::success) {
        report(core::log::Level::warn,
               "ev=physics stage=tick result=fail session=0x%016llX status=%u ticks=%llu",
               static_cast<unsigned long long>(entry.groupSessionId),
               static_cast<unsigned>(result.status),
               static_cast<unsigned long long>(entry.ticks));
        close_bound(table, slot);
        return;
    }
    ++entry.ticks;
    // One line a second. The tick itself is silent, so without this a running world and a stalled
    // one read the same.
    constexpr std::uint64_t kReportEveryTicks = 30;
    if (entry.ticks % kReportEveryTicks != 0) {
        return;
    }
    world::WorldSnapshot snapshot{};
    const HostStatus copied = host->snapshot(entry.world, snapshot);
    report(core::log::Level::debug,
           "ev=physics stage=tick result=ok session=0x%016llX activity=0x%016llX ticks=%llu "
           "stages=%zu actors=%zu peers=%zu",
           static_cast<unsigned long long>(entry.groupSessionId),
           static_cast<unsigned long long>(entry.activitySessionId),
           static_cast<unsigned long long>(entry.ticks),
           result.stageCount,
           copied == HostStatus::success ? snapshot.actorCount : 0U,
           table.coordinators[slot].peer_count());

    // Replication-drive probe (behind reconstruct_mission_policy). The fan-out that would carry the
    // ticked world to the peer -- reconcile -> prepare_frame -> settle_frame -- has no caller today.
    // Drive it minimally here and witness where it stalls before wiring it for real: reconcile folds
    // the snapshot into stable allocations; prepare_frame builds a frame from the peer's planned
    // actors. The frame is settled as lost, never sent, so this measures whether frames BUILD (and
    // names the first missing rung when they do not), not enemies. All three calls are fail-closed.
    if (copied != HostStatus::success
        || !core::settings::get().server.activation.reconstructMissionPolicy) {
        return;
    }
    PeerServiceAccess probeServices{};
    if (host->peer_services(entry.world, entry.peer, probeServices) != HostStatus::success
        || probeServices.replication == nullptr || probeServices.common == nullptr) {
        return;
    }
    static std::uint64_t probeGeneration = 0;  // Worker-thread only; a plain counter is enough.
    const replication::WorldReconcileResult reconciled =
        table.coordinators[slot].reconcile(snapshot);
    // Populate the planner from the reconciled coordinator actors. synchronize_peer would do this
    // through an interest pass, but that needs a real spatial PeerView; the probe has none, so it
    // publishes every live actor directly. Without this the planner stays empty and prepare_next
    // returns idle (the observed stall: coord_actors>0 but entity=0).
    const std::size_t published =
        table.coordinators[slot].probe_publish_actors(*probeServices.replication);
    // prepare_frame's first gate is common::ready (phase==confirmed). The common handshake that would
    // confirm it (observe fed by inbound patch-epoch/type-52) has no caller yet, so drive it locally
    // with a synthetic root. Nothing is sent, so this only unblocks the encode -- not a real send.
    const bool commonReady = probe_confirm_common(*probeServices.common);
    replication::FrameContribution contribution{};
    const std::uint64_t packetGeneration = ++probeGeneration;
    // Drive a SQUAD entity payload (type 1) so the probe exercises the recovered squad baseline
    // schema through the encode path, not just the empty sobject fallback. The write callback emits
    // the 55-bit baseline; nothing is sent, so this witnesses whether a squad frame builds+encodes.
    replication::EntityPayloadPlan squadPlan{};
    squadPlan.type = middleware::gameplay::external::EntityType::squad;
    const replication::FramePrepareResult framed =
        table.coordinators[slot].prepare_frame(*probeServices.replication, *probeServices.common,
                                               packetGeneration, &squadPlan, contribution);
    report(core::log::Level::info,
           "ev=physics stage=replicate reconcile=%u coord_actors=%zu published=%zu common_ready=%d "
           "frame=%u common=%d entity=%d",
           static_cast<unsigned>(reconciled), table.coordinators[slot].actor_count(), published,
           commonReady ? 1 : 0, static_cast<unsigned>(framed),
           contribution.commonPresent ? 1 : 0, contribution.entityPresent ? 1 : 0);
    if (framed == replication::FramePrepareResult::ready
        || framed == replication::FramePrepareResult::full) {
        // Frame detail: is the built record a create (lifecycle!=0, baseline carries the 55-bit squad
        // schema) or an update (lifecycle==0, my update part emits nothing)? bits=39 alone can't tell
        // the two apart, so log the record shape once the frame is ready.
        const auto& builtRecord = contribution.frame.entities.record;
        report(core::log::Level::info,
               "ev=physics stage=frame_detail present=%d flags=0x%X type=%u life=%u base_bytes=%u "
               "upd_bytes=%u",
               contribution.frame.entities.recordPresent ? 1 : 0,
               static_cast<unsigned>(builtRecord.flags), static_cast<unsigned>(builtRecord.type),
               static_cast<unsigned>(builtRecord.lifecycleRevision),
               static_cast<unsigned>(builtRecord.baseline.byteCount),
               static_cast<unsigned>(builtRecord.update.byteCount));
        // Measure the squad baseline callback in isolation. The create frame encodes to only 39 bits,
        // too few for the 55-bit baseline, so confirm whether the callback itself emits those bits.
        {
            const auto& baseCodec = replication::scriptless_payload_codec();
            middleware::encoding::bits::Writer measure =
                middleware::encoding::bits::Writer::measuring();
            middleware::gameplay::external::TypePayload emptyPayload{};
            const bool baselineOk =
                baseCodec.write != nullptr
                && baseCodec.write(baseCodec.context, builtRecord.token,
                                   middleware::gameplay::external::EntityType::squad,
                                   middleware::gameplay::external::TypePayloadPart::baseline,
                                   emptyPayload, measure);
            std::size_t baselineBytes = 0;
            const bool baselineFinished = baselineOk && measure.finish(baselineBytes);
            report(core::log::Level::info,
                   "ev=physics stage=baseline_probe ok=%d bits=%zu bytes=%zu maxbase=%zu",
                   baselineFinished ? 1 : 0, measure.bit_count(), baselineBytes,
                   baseCodec.maximumBaselineBits);
        }
        // Encode witness (next rung of the drive). write_external_entity_frame has no caller in the
        // tree: the codec header marks its four entry points "no caller yet ... wait on the
        // gameplay_external_body gate". Drive it here against the scriptless codec to test whether
        // the compiled encode turns the drive's real built frame into a bit stream. The bytes are
        // witnessed, not sent: the established packet carries only ack + reliable queues (no state
        // slot), and the native client has no decoder for an external frame. So this measures
        // whether the frame ENCODES, one rung past whether it builds -- still not enemies.
        std::array<std::byte, 2048> frameBytes{};
        middleware::encoding::bits::Writer frameWriter(frameBytes);
        std::size_t frameByteCount = 0;
        const bool encoded = middleware::gameplay::external::write_external_entity_frame(
            frameWriter, replication::scriptless_payload_codec(), contribution.frame);
        const bool finished = encoded && frameWriter.finish(frameByteCount);
        report(core::log::Level::info,
               "ev=physics stage=encode result=%s bits=%zu bytes=%zu common=%d entity=%d",
               finished ? "ok" : "fail",
               frameWriter.bit_count(),
               frameByteCount,
               contribution.commonPresent ? 1 : 0,
               contribution.entityPresent ? 1 : 0);
        // Hand the encoded body to the established writer, which appends it to the next
        // acknowledgement when gameplay_external_body is also on. This is the rung the codec header
        // was waiting for: the frame stops being witnessed and starts being sent.
        if (finished && frameWriter.bit_count() > 0) {
            const bool staged = sunrise::server::gameplay::peer::stage_external_frame(
                std::span<const std::byte>(frameBytes.data(), frameByteCount),
                frameWriter.bit_count());
            report(core::log::Level::info, "ev=physics stage=stage result=%s bits=%zu bytes=%zu",
                   staged ? "ok" : "refused", frameWriter.bit_count(), frameByteCount);
        }
        // The outcome stays `lost` even when the body is staged: the send is unacknowledged, and a
        // create baseline that repeats every pass is what a first live test wants. Advancing the
        // lifecycle here would turn the next frame into an update and change two things at once.
        static_cast<void>(table.coordinators[slot].settle_frame(*probeServices.replication,
                                                                *probeServices.common, contribution,
                                                                packetGeneration,
                                                                replication::Outcome::lost));
    }
}

/**
 * True when an `encounter_test.flag` file sits next to this module. Dev gate for the force-open
 * diagnostic below: the offline roster never grants an activity epoch, so a normal bind never opens
 * a world. With the flag present, the reconcile pass force-opens one world under the blueprint
 * encounter policy so the engine can be exercised in the live game.
 */
[[nodiscard]] bool encounter_test_flag() noexcept {
    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                               | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&encounter_test_flag), &module)
        == 0) {
        return false;
    }
    wchar_t path[MAX_PATH];
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    std::wstring flag(path, length);
    const std::size_t slash = flag.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return false;
    }
    flag.replace(slash + 1, std::wstring::npos, L"encounter_test.flag");
    return GetFileAttributesW(flag.c_str()) != INVALID_FILE_ATTRIBUTES;
}

/** Dev force-open backoff, so a world that opens then fails to tick is not reopened every slice. */
std::uint64_t g_nextForceOpen = 0;

/**
 * Dev diagnostic: force one world open under the blueprint encounter policy.
 *
 * The offline roster never grants an activity epoch, so `open_bound` never clears its lease check
 * and no world opens. With the flag present, this opens a world directly from a published host row,
 * with no peer bound, and marks the slot so the reconcile pass leaves it alone. `open_world`
 * installs the blueprint policy (its null-policy-plus-flag path) and `tick_bound` then drives it.
 * Actors stay logical until squad replication is wired, so this proves the engine runs live; it
 * does not yet make enemies visible on the client.
 * @return True when a world was force-opened this pass.
 */
[[nodiscard]] bool force_open_test(Storage& table,
                                   const std::array<group::HostSessionRow, kHostRowCapacity>& rows,
                                   std::size_t rowCount,
                                   std::uint64_t now) noexcept {
    BubbleHost* host = runtime::instance();
    if (host == nullptr) {
        return false;
    }
    std::size_t slot = table.bound.size();
    for (std::size_t index = 0; index < table.bound.size(); ++index) {
        if (table.bound[index].occupied) {
            return false;  // A world is already up; open at most one.
        }
        if (slot == table.bound.size()) {
            slot = index;
        }
    }
    if (slot == table.bound.size()) {
        return false;
    }
    for (std::size_t index = 0; index < rowCount; ++index) {
        const group::HostSessionRow& row = rows[index];
        if (row.generation == 0 || row.hostSessionId == 0) {
            continue;
        }
        WorldOpenRequest request{};
        request.scene.stableSceneId = row.hostSessionId;
        request.scene.contentBuild = kSceneContentBuild;
        request.scene.bubble = static_cast<std::uint32_t>(row.regionIndex);
        request.logicalWorldId = row.hostSessionId;
        request.activitySessionId = row.hostSessionId;
        request.ownerEpoch = row.generation;
        request.deterministicSeed = row.hostSessionId;
        request.millimetersPerUnit = kMillimetersPerUnit;
        // A real scene carries its extents from the destination layout; the force-open world has
        // none, so the backend keeps the zero box and refuses the first placed body (the encounter
        // trigger). Give it a wide bound so the trigger's static body fits and the tick stays healthy.
        request.scene.bounds.minimum = {-5000.0F, -5000.0F, -5000.0F};
        request.scene.bounds.maximum = {5000.0F, 5000.0F, 5000.0F};
        Bound entry{};
        const HostStatus opened = host->open_world(request, nullptr, entry.world);
        report(core::log::Level::info,
               "ev=encounter stage=force_open result=%s activity=0x%016llX region=%d status=%u",
               opened == HostStatus::success ? "ok" : "fail",
               static_cast<unsigned long long>(row.hostSessionId),
               row.regionIndex,
               static_cast<unsigned>(opened));
        if (opened != HostStatus::success) {
            continue;
        }
        entry.groupSessionId = row.groupSessionId;
        entry.activitySessionId = row.hostSessionId;
        entry.hostGeneration = row.generation;
        entry.nextTick = now;
        entry.occupied = true;
        entry.testForced = true;
        table.bound[slot] = entry;
        return true;
    }
    return false;
}

/**
 * Runs one bridge pass. Only the worker thread calls this.
 * @param now Monotonic tick count in milliseconds.
 * @param reconcile True to run the close and open passes as well as the ticks.
 */
void run_pass(std::uint64_t now, bool reconcile) noexcept {
    if (runtime::instance() == nullptr) {
        return;
    }
    Storage* table = storage();
    if (table == nullptr) {
        return;
    }
    if (!reconcile) {
        for (std::size_t slot = 0; slot < table->bound.size(); ++slot) {
            if (table->bound[slot].occupied) {
                tick_bound(*table, slot, now);
            }
        }
        return;
    }
    std::array<group::AdmittedRow, kAdmittedCapacity> admitted{};
    std::size_t admittedCount = 0;
    group::snapshot_admitted(admitted, admittedCount);
    std::array<group::HostSessionRow, kHostRowCapacity> rows{};
    std::size_t rowCount = 0;
    group::snapshot_host_sessions(rows, rowCount);

    // Closing runs first, so a peer that left this slice frees its world for the peer that
    // replaces it in the same slice.
    for (std::size_t slot = 0; slot < table->bound.size(); ++slot) {
        Bound& entry = table->bound[slot];
        if (!entry.occupied) {
            continue;
        }
        if (entry.testForced) {
            continue;  // Dev force-open: no roster row backs it, so reconcile never closes it.
        }
        const group::HostSessionRow* row = find_host_row(rows, rowCount, entry.groupSessionId);
        // A rebound host row is a different activity, so the world it opened is finished even
        // though the group session id has not changed.
        const bool current = row != nullptr && row->generation == entry.hostGeneration
                             && row->hostSessionId == entry.activitySessionId;
        const bool joined = still_joined(admitted, admittedCount, entry.groupSessionId);
        if (!current || !joined) {
            // Witness: name why a bound world is reaped so a same-tick open/close is diagnosable.
            report(core::log::Level::warn,
                   "ev=physics stage=world result=reap session=0x%016llX reason=%s row_found=%d "
                   "gen_row=%llu gen_entry=%llu joined=%d",
                   static_cast<unsigned long long>(entry.groupSessionId),
                   !current ? "not_current" : "not_joined",
                   row != nullptr ? 1 : 0,
                   static_cast<unsigned long long>(row != nullptr ? row->generation : 0),
                   static_cast<unsigned long long>(entry.hostGeneration),
                   joined ? 1 : 0);
            const std::uint64_t closed = entry.groupSessionId;
            close_bound(*table, slot);
            clear_attempt(*table, closed);
        }
    }

    // Dev diagnostic: when the offline roster never leases an epoch, no peer bind ever opens a
    // world. The flag forces one open so the encounter engine can be driven in the live game.
    if (encounter_test_flag() && now >= g_nextForceOpen) {
        g_nextForceOpen = now + kOpenRetryMs;
        static_cast<void>(force_open_test(*table, rows, rowCount, now));
    }

    for (std::size_t index = 0; index < admittedCount; ++index) {
        const group::AdmittedRow& peerRow = admitted[index];
        if (!peerRow.joinComplete || find_bound(*table, peerRow.sessionId) != table->bound.size()) {
            continue;
        }
        const group::HostSessionRow* row = find_host_row(rows, rowCount, peerRow.sessionId);
        if (row == nullptr) {
            continue;
        }
        std::size_t target = table->bound.size();
        for (std::size_t slot = 0; slot < table->bound.size(); ++slot) {
            if (!table->bound[slot].occupied) {
                target = slot;
                break;
            }
        }
        if (target == table->bound.size()) {
            continue;
        }
        Attempt* attempt = attempt_for(*table, peerRow.sessionId, row->generation);
        if (attempt == nullptr || attempt->failures >= kOpenAttemptLimit
            || now < attempt->nextAttempt) {
            continue;
        }
        if (open_bound(*table, target, peerRow, *row, now)) {
            clear_attempt(*table, peerRow.sessionId);
            continue;
        }
        ++attempt->failures;
        attempt->nextAttempt = now + kOpenRetryMs;
        if (attempt->failures == kOpenAttemptLimit) {
            report(core::log::Level::warn,
                   "ev=physics stage=world result=abandoned session=0x%016llX generation=%llu "
                   "attempts=%u",
                   static_cast<unsigned long long>(peerRow.sessionId),
                   static_cast<unsigned long long>(row->generation),
                   attempt->failures);
        }
    }

    for (std::size_t slot = 0; slot < table->bound.size(); ++slot) {
        if (table->bound[slot].occupied) {
            tick_bound(*table, slot, now);
        }
    }
}

/**
 * Owns the bridge for the whole time it runs.
 * Nothing else touches the table while this thread is alive, so the table needs no lock. The pump
 * only starts and stops it, and it joins before it reads anything.
 * @param parameter Unused.
 * @return Always zero.
 */
DWORD WINAPI worker_main(LPVOID parameter) noexcept {
    static_cast<void>(parameter);
    std::uint64_t nextReconcile = 0;
    for (;;) {
        const std::uint64_t now = GetTickCount64();
        const bool reconcile = now >= nextReconcile;
        if (reconcile) {
            nextReconcile = now + kReconcileIntervalMs;
        }
        run_pass(now, reconcile);
        if (WaitForSingleObject(g_stop, kWorkerSliceMs) == WAIT_OBJECT_0) {
            return 0;
        }
    }
}

/** Starts the worker if the gate is on and it is not already running. */
void start_worker() noexcept {
    if (g_thread != nullptr) {
        return;
    }
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stop == nullptr) {
        return;
    }
    g_thread = CreateThread(nullptr, 0, &worker_main, nullptr, 0, nullptr);
    if (g_thread == nullptr) {
        static_cast<void>(CloseHandle(g_stop));
        g_stop = nullptr;
        report(core::log::Level::warn, "ev=physics stage=worker result=fail reason=thread");
        return;
    }
    report(core::log::Level::info,
           "ev=physics stage=worker result=started slice=%llums",
           static_cast<unsigned long long>(kWorkerSliceMs));
}

/** Signals the worker and waits for it, so the caller owns the table when this returns. */
void stop_worker() noexcept {
    if (g_thread == nullptr) {
        return;
    }
    static_cast<void>(SetEvent(g_stop));
    static_cast<void>(WaitForSingleObject(g_thread, INFINITE));
    static_cast<void>(CloseHandle(g_thread));
    static_cast<void>(CloseHandle(g_stop));
    g_thread = nullptr;
    g_stop = nullptr;
    report(core::log::Level::info, "ev=physics stage=worker result=stopped");
}

} // namespace

/** Starts or stops the bridge worker. The bridge itself runs on that worker, not here. */
void service(std::uint64_t now) noexcept {
    static_cast<void>(now);
    // This runs on the callback pump, which is the game's own render thread. All this may cost it
    // is one settings read: the world ticks belong to the worker.
    if (!core::settings::get().server.activation.physicsHostSession) {
        reset();
        return;
    }
    start_worker();
}

/** Stops the worker, then closes every open world and releases its State context. */
void reset() noexcept {
    // The join comes first. After it this thread is the only one that can reach the table.
    stop_worker();
    Storage* table = g_storage.get();
    if (table != nullptr) {
        for (std::size_t slot = 0; slot < table->bound.size(); ++slot) {
            if (table->bound[slot].occupied) {
                close_bound(*table, slot);
            }
        }
    }
    g_storage.reset();
}

} // namespace sunrise::server::gameplay::physics::host::session
