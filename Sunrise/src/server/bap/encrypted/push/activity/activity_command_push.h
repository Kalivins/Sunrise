#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "../../../internal.h"

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * Appends one server->client `sense_update` (message type 6) command notification, when the
 * activity defaults enable it. Type 6 is a command the client parses and never originates. The
 * body is the current 128-bit patch epoch followed by the settings-authored `commandBody`
 * bit-program, which begins at the delta's presence bit. Nothing is appended unless the client's
 * patch epoch is bound, because a command naming an epoch the client does not hold is discarded.
 * @param session Connection whose bound patch epoch the body echoes.
 * @param scratch Lock-owned transform buffers.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce, advanced only after a complete frame is staged.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, advanced only after the frame exists.
 * @return True when a command frame was staged; false when disabled, unbound, or nothing fit.
 */
[[nodiscard]] bool append_command_notification(Session& session,
                                               Scratch& scratch,
                                               std::span<const std::byte, state::kAesKeySize> key,
                                               std::array<std::byte, state::kBapNonceSize>& nonce,
                                               std::span<std::byte> response,
                                               std::size_t& written) noexcept;

} // namespace sunrise::server::bap::encrypted::push::activity
