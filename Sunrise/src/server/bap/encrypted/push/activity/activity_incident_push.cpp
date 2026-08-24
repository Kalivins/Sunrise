#include "activity_incident_push.h"

#include <Windows.h>

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

/** Advancing target for the incident sweep, one step per emitted incident. */
std::atomic<std::uint32_t> g_incidentSweep{0};

} // namespace

/** Appends one server->client incident notification when the activity defaults enable it. */
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

    // One target per send, captured once so both encode passes agree. The sweep advances the target
    // so a single session walks the space; a fixed target repeats one index.
    const std::uint32_t sweepStep =
        settings.incidentSweepEnabled ? g_incidentSweep.fetch_add(1, std::memory_order_relaxed) : 0;
    const std::uint32_t target = settings.incidentTarget + sweepStep;

    incident::Incident body{};
    body.primaryTarget = target;

    // Measure, then write, the same two-pass contract the roster encoder uses, so a body that does
    // not fit leaves no partial bytes behind. incident::write drops poison and out-of-range targets,
    // so nothing is staged for a target the client cannot safely resolve.
    bits::Writer measure = bits::Writer::measuring();
    std::size_t requiredSize = 0;
    if (!incident::write(measure, body) || !measure.finish(requiredSize)
        || requiredSize > scratch.responseBody.size()) {
        return false;
    }
    bits::Writer writer(scratch.responseBody);
    std::size_t messageSize = 0;
    if (!incident::write(writer, body) || !writer.finish(messageSize)
        || messageSize != requiredSize) {
        return false;
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

    // Witness: the emitted target and body bytes, so a target that produced an in-game effect can be
    // read back from the log and a client that rejects a well-formed incident is told apart from one
    // that never received it.
    if (core::log::accepts(core::log::Channel::server, core::log::Level::debug)) {
        std::array<char, core::log::kLineCapacity> line{};
        int used = std::snprintf(line.data(),
                                 line.size(),
                                 "ev=gameplay stage=incident result=%s target=%u bytes=%zu hex=",
                                 encoded ? "ok" : "fail",
                                 target,
                                 encoded ? messageSize : 0);
        for (std::size_t index = 0; encoded && index < messageSize && used > 0
                                    && static_cast<std::size_t>(used) + 3 < line.size();
             ++index) {
            const int printed =
                std::snprintf(line.data() + used,
                              line.size() - static_cast<std::size_t>(used),
                              "%02x",
                              static_cast<unsigned>(
                                  std::to_integer<unsigned char>(scratch.responseBody[index])));
            if (printed <= 0) {
                break;
            }
            used += printed;
        }
        if (used > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(used)});
        }
    }

    SecureZeroMemory(scratch.responseBody.data(), messageSize);
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

} // namespace sunrise::server::bap::encrypted::push::activity
