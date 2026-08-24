#include "activity_incident_push.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../../../../core/logging/log.h"
#include "../../../../../middleware/bap/activity_message/incident.h"
#include "../../../../../middleware/encoding/bit_writer.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "../../../../../state/activity/defaults/activity_defaults_snapshot.h"
#include "../../../../../state/activity/defaults/definition.h"
#include "activity_notification_frame.h"
#include "internal.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace incident = middleware::bap::activity_message::incident;
namespace bits = middleware::encoding::bits;
namespace defaults = state::activity::defaults;

/** Advancing base for the incident sweep, one step per emitted incident (block-aware). */
std::atomic<std::uint32_t> g_incidentSweep{0};

/** Ceiling on incidents staged in one keepalive, so a block sweep cannot exhaust the frame buffer. */
constexpr std::uint32_t kMaxIncidentsPerSend = 128;

/** Outcome of one incident emit, so the sweep advances past dropped targets but retries no-fit ones. */
enum class EmitResult {
    /** A frame was staged for the target. */
    staged,
    /** The encoder refused the target (poison or out of range); skip it and move on. */
    dropped,
    /** The target is valid but the frame did not fit the buffer; stop and retry it next send. */
    noFit,
};

/** Stages one incident frame for `target`, advancing nonce and written only when the frame fits. */
[[nodiscard]] EmitResult emit_one(Session& session,
                                  Scratch& scratch,
                                  std::span<const std::byte, state::kAesKeySize> key,
                                  std::array<std::byte, state::kBapNonceSize>& nonce,
                                  std::span<std::byte> response,
                                  std::size_t& written,
                                  std::uint32_t target) noexcept {
    incident::Incident body{};
    body.primaryTarget = target;

    bits::Writer measure = bits::Writer::measuring();
    std::size_t requiredSize = 0;
    if (!incident::write(measure, body) || !measure.finish(requiredSize)
        || requiredSize > scratch.responseBody.size()) {
        return EmitResult::dropped;
    }
    bits::Writer writer(scratch.responseBody);
    std::size_t messageSize = 0;
    if (!incident::write(writer, body) || !writer.finish(messageSize)
        || messageSize != requiredSize) {
        return EmitResult::dropped;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    const bool encoded =
        append_notification_frame(scratch,
                                  session.activity.session.sessionId,
                                  incident::kMessageType,
                                  std::span(scratch.responseBody).first(messageSize),
                                  key,
                                  nonce,
                                  response,
                                  written);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
    } else {
        if (written > initialWritten) {
            SecureZeroMemory(response.data() + initialWritten, written - initialWritten);
        }
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(scratch.responseBody.data(), messageSize);
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded ? EmitResult::staged : EmitResult::noFit;
}

} // namespace

/** Appends server->client incident notification(s) when the activity defaults enable it. */
bool append_incident_notification(Session& session,
                                  Scratch& scratch,
                                  std::span<const std::byte, state::kAesKeySize> key,
                                  std::array<std::byte, state::kBapNonceSize>& nonce,
                                  std::span<std::byte> response,
                                  std::size_t& written) noexcept {
    if (written > response.size()) {
        return false;
    }
    defaults::ActivityDefaults settings{};
    defaults::snapshot(settings);
    if (!settings.incidentEmitEnabled) {
        return false;
    }
    // Send only once the client is fully established: the patch epoch binds after the roster is
    // received and applied, the same readiness the client showed when it accepted (and rejected) a
    // type-6 command. An incident sent earlier reaches a client not yet in the activity.
    if (!session.activityPatchEpoch.seen
        || session.activityPatchEpoch.bindingGeneration != session.activity.bindingGeneration) {
        return false;
    }

    // A fixed target sends once; a sweep sends a block of consecutive targets. The base advances only
    // by what was consumed this send (staged + encoder-dropped), so a target skipped for want of
    // buffer space is retried next keepalive rather than silently lost. Keepalives are serialized per
    // session, so the load/store around the shared base needs no stronger ordering.
    const std::uint32_t blockSize =
        settings.incidentSweepEnabled
            ? std::min(std::max(settings.incidentBlockSize, 1U), kMaxIncidentsPerSend)
            : 1U;
    const std::uint32_t sweepBase =
        settings.incidentSweepEnabled ? g_incidentSweep.load(std::memory_order_relaxed) : 0U;

    std::uint32_t staged = 0;
    std::uint32_t processed = 0;
    const std::uint32_t firstTarget = settings.incidentTarget + sweepBase;
    std::uint32_t lastTarget = firstTarget;
    for (std::uint32_t index = 0; index < blockSize; ++index) {
        const std::uint32_t target = settings.incidentTarget + sweepBase + index;
        const EmitResult result = emit_one(session, scratch, key, nonce, response, written, target);
        if (result == EmitResult::noFit) {
            break;
        }
        ++processed;
        if (result == EmitResult::staged) {
            ++staged;
            lastTarget = target;
        }
    }
    if (settings.incidentSweepEnabled) {
        g_incidentSweep.store(sweepBase + processed, std::memory_order_relaxed);
    }

    // Witness: the block range and how many frames were staged, so an on-screen effect can be mapped
    // to the keepalive's target block; a block of one logs the single target for the fine sweep.
    if (core::log::accepts(core::log::Channel::server, core::log::Level::debug)) {
        std::array<char, core::log::kLineCapacity> line{};
        const int used = std::snprintf(
            line.data(),
            line.size(),
            "ev=gameplay stage=incident result=%s block_start=%u block_size=%u staged=%u last=%u",
            staged > 0 ? "ok" : "fail",
            firstTarget,
            blockSize,
            staged,
            lastTarget);
        if (used > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(used)});
        }
    }

    return staged > 0;
}

} // namespace sunrise::server::bap::encrypted::push::activity
