#pragma once

#include <cstdint>

namespace sunrise::server::gameplay::reconstruct {

/**
 * The synthetic group-session key R1 claims its host row under. R2 reads the row's allocated target
 * back through it (host_session_for_group), so the synthetic join names the same session.
 */
inline constexpr std::uint64_t kReconstructGroupSession = 0x5211000000000001ULL;

/**
 * Rung R1 of the offline mission-reconstruction ladder.
 *
 * When the `reconstruct_host_session` activation gate is on and an activity override is active,
 * seeds one source-bound activity-host row for the forced destination: it commits a source
 * activity-session record carrying the forced package name, then claims a host row against it, so
 * the service pump's `allocate_claimed_host_sessions` can allocate its target. Once ready,
 * `host_session_for_activity` finds the row — the R1 witness. With the gate off, or once the
 * override clears, it releases the source record and its retained host generation and serves
 * nothing. Runs on the host-session service pump, outside any staged push.
 *
 * This produces no wire output on its own. The synthetic join (R2) and the peer bind (R4) build on
 * the row this leaves ready.
 */
void reconstruct_service() noexcept;

} // namespace sunrise::server::gameplay::reconstruct
