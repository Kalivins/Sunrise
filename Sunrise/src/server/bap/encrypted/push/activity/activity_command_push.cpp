#include "activity_command_push.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../../../../core/logging/log.h"
#include "../../../../../middleware/bap/activity_message/sense_update.h"
#include "../../../../../middleware/encoding/bit_writer.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "../../../../../state/activity/defaults/activity_defaults_snapshot.h"
#include "../../../../../state/activity/defaults/definition.h"
#include "activity_notification_frame.h"
#include "internal.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace message = middleware::bap::activity_message::sense_update;
namespace patch_epoch = middleware::bap::activity_message::patch_epoch;
namespace bits = middleware::encoding::bits;
namespace defaults = state::activity::defaults;

/**
 * Writes one sense_update body through one writer: the fixed 128-bit epoch, then the authored
 * bit-program that begins at the delta's presence bit.
 * @param writer Real or measuring writer positioned at the first bit.
 * @param epoch Patch epoch the client must already hold.
 * @param steps Bit-program fields, most significant bit first.
 * @param count Number of valid steps.
 * @return True when every field fit.
 */
[[nodiscard]] bool write_command_body(bits::Writer& writer,
                                      const patch_epoch::PatchEpoch& epoch,
                                      const defaults::CommandBodyStep* steps,
                                      std::size_t count) noexcept {
    bool encoded = writer.write(epoch.first, message::kEpochFieldWidth)
                   && writer.write(epoch.second, message::kEpochFieldWidth);
    for (std::size_t index = 0; encoded && index < count; ++index) {
        encoded = writer.write(steps[index].value, steps[index].width);
    }
    return encoded;
}

} // namespace

/** Appends one server->client sense_update command when the activity defaults enable it. */
bool append_command_notification(Session& session,
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
    if (!settings.commandEmitEnabled) {
        return false;
    }
    // A command echoes the epoch the roster carried. A body sent before the client's epoch is bound
    // names an epoch the client does not hold and is discarded on arrival.
    if (!session.activityPatchEpoch.seen
        || session.activityPatchEpoch.bindingGeneration != session.activity.bindingGeneration) {
        return false;
    }
    const std::size_t count = settings.commandBodyCount <= settings.commandBody.size()
                                  ? settings.commandBodyCount
                                  : settings.commandBody.size();

    // Measure, then write, the same two-pass contract the roster encoder uses, so a body that does
    // not fit leaves no partial bytes behind.
    bits::Writer measure = bits::Writer::measuring();
    std::size_t requiredSize = 0;
    if (!write_command_body(measure, session.activityPatchEpoch.value, settings.commandBody.data(),
                            count)
        || !measure.finish(requiredSize) || requiredSize > scratch.responseBody.size()) {
        return false;
    }
    bits::Writer writer(scratch.responseBody);
    std::size_t messageSize = 0;
    if (!write_command_body(writer, session.activityPatchEpoch.value, settings.commandBody.data(),
                            count)
        || !writer.finish(messageSize) || messageSize != requiredSize) {
        return false;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    const bool encoded =
        append_notification_frame(scratch,
                                  session.activity.session.sessionId,
                                  message::kMessageType,
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

    // Witness: the emitted body's exact bytes, so the layout can be checked against the intended
    // bit-program and a client that rejects a well-formed body is distinguished from one that never
    // received it.
    if (core::log::accepts(core::log::Channel::server, core::log::Level::debug)) {
        std::array<char, core::log::kLineCapacity> line{};
        int used = std::snprintf(line.data(),
                                 line.size(),
                                 "ev=gameplay stage=command result=%s bytes=%zu steps=%zu hex=",
                                 encoded ? "ok" : "fail",
                                 encoded ? messageSize : 0,
                                 count);
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
