#pragma once

#include <cstddef>
#include <span>

namespace sunrise::server::gameplay::peer {

/**
 * Largest external entity body the established writer will carry.
 * A built entity frame measures tens of bits today; the bound exists so a malformed or unexpectedly
 * large body can never crowd out the acknowledgement it rides with.
 */
inline constexpr std::size_t kExternalFrameCapacity = 256;

/**
 * Hands one encoded external entity frame from the physics replication pass to the established
 * packet writer.
 *
 * The replication pass and the transport run on different threads and neither owns the other, so the
 * frame crosses through one lock-protected slot rather than a shared object. The slot holds at most
 * one frame: a newer frame replaces an unsent older one, because the client wants the current world
 * state, not a backlog.
 *
 * @param body Encoded frame bytes, as produced by write_external_entity_frame.
 * @param bitCount Payload bits in body; the trailing bits of the final byte are padding and are not
 *        re-emitted, so the packet stays bit-exact.
 * @return True when the frame was stored; false when it exceeds kExternalFrameCapacity.
 */
[[nodiscard]] bool stage_external_frame(std::span<const std::byte> body,
                                        std::size_t bitCount) noexcept;

/**
 * Removes the staged frame, if one is waiting.
 * A frame is sent at most once: taking it empties the slot, so an acknowledgement that carries no
 * body cannot repeat the previous one.
 * @param body Receives the frame bytes; must hold kExternalFrameCapacity.
 * @param bitCount Receives the payload bit count.
 * @return True when a frame was taken.
 */
[[nodiscard]] bool take_external_frame(std::span<std::byte> body, std::size_t& bitCount) noexcept;

} // namespace sunrise::server::gameplay::peer
