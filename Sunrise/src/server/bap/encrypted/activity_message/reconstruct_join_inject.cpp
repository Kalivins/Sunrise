#include "reconstruct_join_inject.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../../../core/logging/log.h"
#include "../../../../core/settings/settings.h"
#include "../../../../middleware/bap/activity_message/activity_join_request_parser.h"
#include "../../../../middleware/bap/activity_message/activity_message_request_parser.h"
#include "../../../../middleware/encoding/bit_writer.h"
#include "../../../../middleware/encoding/byte_order.h"
#include "../../../../state/account/account_state.h"
#include "../../../../state/runtime/runtime.h"
#include "../../../gameplay/group/group_host_sessions.h"
#include "../../../gameplay/reconstruct/reconstruct_host_session.h"

namespace sunrise::server::bap::encrypted::activity_message {
namespace {

namespace enc = middleware::encoding;
namespace msg = middleware::bap::activity_message;
namespace joinreq = middleware::bap::activity_message::join_request;
namespace group = ::sunrise::server::gameplay::group;
namespace reconstruct = ::sunrise::server::gameplay::reconstruct;

/** Correlation the synthetic join carries. Nonzero, and otherwise unread by prepare_join. */
constexpr std::uint32_t kCorrelation = 1;
/** Member key the join carries. prepare_join sets both sides equal, so any value commits. */
constexpr std::uint64_t kMemberKey = 0x5211000000000002ULL;
/** The signed-in character sits at this bit, 64 bits most-significant-first, after the prefix. */
constexpr std::size_t kCharacterSoidBit = 330;
/** correlation(32) + sessionId(64) + memberKey(64) + zero fill(170) + characterSoid(64). */
constexpr std::size_t kPayloadBits = 394;
constexpr std::size_t kPayloadBytes = (kPayloadBits + 7) / 8;
/** accountHandle(8) + discriminator(1) + messageType(4) + payloadLength(4) + peerHeardMask(4). */
constexpr std::size_t kEnvelopePrefix = 21;
constexpr std::size_t kEnvelopeBytes = kEnvelopePrefix + kPayloadBytes;
constexpr std::uint32_t kJoinMessageType = 3;

/** True once a synthetic join has been injected for the current host-row lifetime. */
bool g_injected = false;

/**
 * Builds the join payload with its mixed endianness: correlation big-endian, sessionId big-endian,
 * memberKey little-endian, then the signed character at bit 330 most-significant-first. The fill
 * between the prefix and the character stays zero; prepare_join reads none of it.
 * @return True when every field fit and the payload is exactly kPayloadBytes long.
 */
[[nodiscard]] bool build_payload(std::span<std::byte, kPayloadBytes> out,
                                 std::uint64_t target,
                                 std::uint64_t characterSoid) noexcept {
    enc::bits::Writer writer(out);
    bool ok = writer.write(kCorrelation, 32) && writer.write(target, 64);
    // memberKey little-endian: one byte-aligned write each, low byte first.
    for (std::size_t index = 0; ok && index < enc::kU64Size; ++index) {
        ok = writer.write((kMemberKey >> (index * enc::kBitsPerByte)) & 0xFFU, 8);
    }
    // Zero fill from the prefix's end up to the character bit.
    std::size_t fill = kCharacterSoidBit - writer.bit_count();
    while (ok && fill != 0) {
        const std::uint8_t width = fill > 64 ? 64 : static_cast<std::uint8_t>(fill);
        ok = writer.write(0, width);
        fill -= width;
    }
    ok = ok && writer.write(characterSoid, 64);
    std::size_t written = 0;
    return ok && writer.finish(written) && written == kPayloadBytes;
}

/** Builds the whole svc8 join envelope. @return True when every field fit. */
[[nodiscard]] bool build_envelope(std::span<std::byte, kEnvelopeBytes> out,
                                  std::uint64_t target,
                                  std::uint64_t characterSoid) noexcept {
    enc::write_u64_be(out.subspan<0, enc::kU64Size>(), target);
    out[enc::kU64Size] = msg::kTransportDiscriminator;
    enc::write_u32_be(out.subspan<9, enc::kU32Size>(), kJoinMessageType);
    enc::write_u32_be(out.subspan<13, enc::kU32Size>(), static_cast<std::uint32_t>(kPayloadBytes));
    enc::write_u32_be(out.subspan<17, enc::kU32Size>(), 0);
    return build_payload(out.subspan<kEnvelopePrefix, kPayloadBytes>(), target, characterSoid);
}

/**
 * Confirms the built envelope parses back to exactly the identities we intended. This round-trip is
 * the ONLY thing that proves the characterSoid bit offset (330) and the mixed endianness are right:
 * the builder writes those on faith, and only re-reading through the real parser checks them. Never
 * remove it, even the day it looks redundant, or the endianness and offset mines go back in unseen.
 */
[[nodiscard]] bool round_trips(std::span<const std::byte> body,
                               std::uint64_t target,
                               std::uint64_t characterSoid) noexcept {
    msg::Request request{};
    if (!msg::parse_request(body, request) || request.messageType != kJoinMessageType
        || request.accountHandle != target) {
        return false;
    }
    msg::JoinRequest join{};
    return joinreq::parse_join_request(request.payload, join) && join.sessionId == target
           && join.memberKey == kMemberKey && join.characterSoid == characterSoid;
}

/** @return The bind path prepare_join chose, which decides whether the commit takes a host retain. */
[[nodiscard]] const char* intent_name(BindingIntent intent) noexcept {
    switch (intent) {
    case BindingIntent::preserveCurrent:
        return "preserveCurrent";
    case BindingIntent::publicTarget:
        return "publicTarget";
    default:
        return "none";
    }
}

} // namespace

bool inject_reconstruct_join(const ActivityClientBinding& binding,
                             ActivityPlan& plan,
                             bool& hasTransaction) noexcept {
    plan = {};
    hasTransaction = false;
    if (!core::settings::get().server.activation.reconstructHostSession) {
        return false;
    }
    // R1's row carries the target. No ready row means R1 has not allocated one yet, or the override
    // was cut and it tore down; either way re-arm and wait for the next lifetime.
    group::HostSessionBinding host{};
    if (!group::host_session_for_group(reconstruct::kReconstructGroupSession, host)) {
        g_injected = false;
        return false;
    }
    if (g_injected) {
        return false;
    }
    const std::uint64_t target = host.target.sessionId;
    // The roster publishes this character as its participation key; the join must carry the same or
    // the client binds nobody. This is the exact expression roster_player_key uses when the join
    // carries no character (activity_roster_snapshot.cpp:46-59), so it matches by construction.
    // Recalculating is right while the selected character does not change between the roster push
    // and here; capturing the value the roster actually published would be strictly safer.
    const std::uint64_t characterSoid =
        state::account::selected_character_soid(state::account_snapshot());

    std::array<std::byte, kEnvelopeBytes> body{};
    if (!build_envelope(body, target, characterSoid) || !round_trips(body, target, characterSoid)) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=gameplay stage=reconstruct_join result=fail reason=encode");
        return false;
    }

    const bool processed = process(binding, body, plan, hasTransaction);
    g_injected = true;
    // The two bind paths diverge in the commit: publicTarget takes a second host-session retain and
    // preserveCurrent does not (service_outcome_commit.cpp:149-169). That retain is exactly what
    // R3's teardown guard must detect, so which path this took is not optional to know.
    std::array<char, 96> line{};
    const int count = std::snprintf(line.data(),
                                    line.size(),
                                    "ev=gameplay stage=reconstruct_join result=%s intent=%s",
                                    processed ? "injected" : "rejected",
                                    intent_name(plan.bindingIntent));
    if (count > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(count)});
    }
    return processed;
}

} // namespace sunrise::server::bap::encrypted::activity_message
