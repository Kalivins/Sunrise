#include "join_descriptor.h"

#include <algorithm>
#include <span>

namespace sunrise::middleware::gameplay::descriptor {

namespace {

/** The machine identity occupies the first eight bytes. */
constexpr std::size_t kMachineOffset = 0;
/** The NetAddr follows the machine identity. */
constexpr std::size_t kNetAddrOffset = 8;
/** The IPv4 address opens the first local entry, in network byte order. */
constexpr std::size_t kAddressOffset = 0;
/** The UDP port follows the address, low byte first. The IPv4 beside it stays network order. */
constexpr std::size_t kPortOffset = 4;
/** The public entry follows five 6-byte local entries, and carries the same two fields. */
constexpr std::size_t kPublicAddressOffset = 30;
/** The public UDP port follows the public address, low byte first. */
constexpr std::size_t kPublicPortOffset = 34;
/** The NAT type closes the address body at offset 40. */
constexpr std::size_t kNatTypeOffset = 40;
/** NAT type 1 reads as open. Zero reads as unknown and leaves the address unroutable. */
constexpr std::byte kNatTypeOpen{1};
/** The transport method is the last NetAddr byte. */
constexpr std::size_t kMethodOffset = kNetAddrSize - 1;
/** Method 0 selects the direct path. Methods 6 and 7 would select the relay instead. */
constexpr std::byte kDirectMethod{0};
/** The online session id occupies the tail, low half first. */
constexpr std::size_t kSessionOffset = 110;
/** Bits in one byte. */
constexpr unsigned kByteBits = 8;
/** Mask of one byte. */
constexpr std::uint64_t kByteMask = 0xFF;
/** The advertised port must be even. */
constexpr std::uint16_t kPortAlignment = 2;

/**
 * Writes one unsigned value in network byte order.
 * @param output Field storage.
 * @param offset First byte of the field.
 * @param value Host-order value.
 * @param width Field width in bytes.
 */
void write_network_order(std::span<std::byte> output,
                         std::size_t offset,
                         std::uint64_t value,
                         std::size_t width) noexcept {
    for (std::size_t index = 0; index < width; ++index) {
        const unsigned shift = static_cast<unsigned>(width - 1 - index) * kByteBits;
        output[offset + index] = static_cast<std::byte>((value >> shift) & kByteMask);
    }
}

/**
 * Writes one unsigned value low byte first.
 * @param output Field storage.
 * @param offset First byte of the field.
 * @param value Host-order value.
 * @param width Field width in bytes.
 */
void write_memory_order(std::span<std::byte> output,
                        std::size_t offset,
                        std::uint64_t value,
                        std::size_t width) noexcept {
    for (std::size_t index = 0; index < width; ++index) {
        const unsigned shift = static_cast<unsigned>(index) * kByteBits;
        output[offset + index] = static_cast<std::byte>((value >> shift) & kByteMask);
    }
}

} // namespace

/** Builds one NetAddr for the direct method-0 path. */
void write_net_addr(std::uint32_t address,
                    std::uint16_t port,
                    std::array<std::byte, kNetAddrSize>& output) noexcept {
    output = {};
    write_network_order(output, kAddressOffset, address, sizeof(std::uint32_t));
    write_memory_order(output, kPortOffset, port, sizeof(std::uint16_t));
    write_network_order(output, kPublicAddressOffset, address, sizeof(std::uint32_t));
    write_memory_order(output, kPublicPortOffset, port, sizeof(std::uint16_t));
    output[kNatTypeOffset] = kNatTypeOpen;
    output[kMethodOffset] = kDirectMethod;
}

/** Builds one join descriptor for the direct method-0 path. */
bool build(const JoinEndpoint& endpoint, std::array<std::byte, kDescriptorSize>& output) noexcept {
    if (endpoint.machineId == 0 || endpoint.address == 0 || endpoint.port == 0
        || endpoint.port % kPortAlignment != 0 || endpoint.onlineSessionId == 0) {
        return false;
    }
    std::array<std::byte, kNetAddrSize> netAddr{};
    write_net_addr(endpoint.address, endpoint.port, netAddr);

    // DIAGNOSTIC (2026-08-22): maximal fill of every zero region whose semantics Sunrise's own
    // constants name, to test the whole "descriptor is incomplete" hypothesis in one cycle. A
    // negative here falsifies that entire family and redirects to the untested "missing client
    // state" branch. Replicate local entry 0 into the four empty local entries [6,30) of the
    // NetAddr, so a client that iterates the five entries finds a valid address in each, not a
    // null one. Deliberately leave NetAddr [36,40) and [41,85) untouched: unknown semantics, and
    // noise there could cause a self-inflicted rejection that turns a negative into a fabricated
    // one. Revert once measured.
    constexpr std::size_t kLocalEntrySize = 6;
    for (std::size_t entry = 1; entry < 5; ++entry) {
        std::copy(netAddr.begin(),
                  netAddr.begin() + kLocalEntrySize,
                  netAddr.begin() + entry * kLocalEntrySize);
    }

    std::array<std::byte, kDescriptorSize> candidate{};
    write_memory_order(candidate, kMachineOffset, endpoint.machineId, sizeof(std::uint64_t));
    std::copy(netAddr.begin(), netAddr.end(), candidate.begin() + kNetAddrOffset);
    write_memory_order(candidate, kSessionOffset, endpoint.onlineSessionId, sizeof(std::uint64_t));
    // Fill the join key [94,110) (= dtls::kSecurityKeySize) and the tail [118,128) with markers.
    constexpr std::size_t kJoinKeyOffset = kNetAddrOffset + kNetAddrSize;
    for (std::size_t index = 0; index < 16; ++index) {
        candidate[kJoinKeyOffset + index] = static_cast<std::byte>(0xA0 + index);
    }
    constexpr std::size_t kTailOffset = kSessionOffset + sizeof(std::uint64_t);
    for (std::size_t index = 0; kTailOffset + index < kDescriptorSize; ++index) {
        candidate[kTailOffset + index] = static_cast<std::byte>(0xB0 + index);
    }
    output = candidate;
    return true;
}

} // namespace sunrise::middleware::gameplay::descriptor
