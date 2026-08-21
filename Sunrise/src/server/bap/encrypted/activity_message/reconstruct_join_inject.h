#pragma once

#include "activity_message_route.h"

namespace sunrise::server::bap::encrypted::activity_message {

/**
 * Rung R2 of the offline mission-reconstruction ladder.
 *
 * Once R1's host row is ready and the `reconstruct_host_session` gate is on, injects ONE synthetic
 * activity join (message type 3) that names R1's allocated target session, so the real
 * `prepare_join` -> commit path runs and the join ladder starts without the client ever sending a
 * join. The synthetic request is built envelope-and-payload byte-exact (mixed endianness) and
 * round-tripped through the real parser before it is fed to `process`, so everything downstream is
 * the unsimulated path. Injects once per host-row lifetime; a torn-down row re-arms it.
 *
 * @param binding Activity binding of the connection whose svc8 stream this rides. prepare_join
 *                path 2 (publicTarget) does not read it; it is only carried through to `process`.
 * @param plan Cleared, then receives the join transaction when one is injected.
 * @param hasTransaction Set true when the injected join staged a commit for the caller to route.
 * @return True when a synthetic join was injected this call, so the caller routes `plan` and skips
 *         the real message; false when nothing was injected and the real message must process.
 */
[[nodiscard]] bool inject_reconstruct_join(const ActivityClientBinding& binding,
                                           ActivityPlan& plan,
                                           bool& hasTransaction) noexcept;

} // namespace sunrise::server::bap::encrypted::activity_message
