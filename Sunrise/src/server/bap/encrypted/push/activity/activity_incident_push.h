#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "../../../internal.h"

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * Appends one server->client `incident` (message type 19) notification, when the activity defaults
 * enable it. Unlike the sense_update command (type 6), which the client rejects inbound as an
 * unknown message type, an incident is a gameplay-event trigger the client consumes: its 13-bit
 * primary target indexes the 7,763-record global handler table (spawn rules, spawn sets, encounter
 * directives). The body is the bounded incident bit-program (target, no extras, no selector, no
 * optional block, no payload) written by `incident::write`; the encoder drops poison and
 * out-of-range targets, so a body is staged only for a target the client can safely resolve. With
 * the sweep enabled the target advances by one each send so a single session walks the target space.
 * @param session Connection the frame is staged for.
 * @param scratch Lock-owned transform buffers.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce, advanced only after a complete frame is staged.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, advanced only after the frame exists.
 * @return True when an incident frame was staged; false when disabled, unbound, or nothing fit.
 */
[[nodiscard]] bool append_incident_notification(Session& session,
                                                Scratch& scratch,
                                                std::span<const std::byte, state::kAesKeySize> key,
                                                std::array<std::byte, state::kBapNonceSize>& nonce,
                                                std::span<std::byte> response,
                                                std::size_t& written) noexcept;

} // namespace sunrise::server::bap::encrypted::push::activity
