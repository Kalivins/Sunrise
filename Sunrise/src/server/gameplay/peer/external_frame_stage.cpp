#include "external_frame_stage.h"

#include <Windows.h>

#include <array>
#include <cstring>

namespace sunrise::server::gameplay::peer {
namespace {

/** The single hand-off slot, guarded because the producer and the consumer are different threads. */
SRWLOCK g_lock = SRWLOCK_INIT;
std::array<std::byte, kExternalFrameCapacity> g_body{};
std::size_t g_bitCount = 0;
bool g_present = false;

} // namespace

bool stage_external_frame(std::span<const std::byte> body, std::size_t bitCount) noexcept {
    if (bitCount == 0 || body.size() > kExternalFrameCapacity
        || bitCount > body.size() * 8U) {
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    std::memcpy(g_body.data(), body.data(), body.size());
    g_bitCount = bitCount;
    g_present = true;
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

bool take_external_frame(std::span<std::byte> body, std::size_t& bitCount) noexcept {
    if (body.size() < kExternalFrameCapacity) {
        return false;
    }
    bool taken = false;
    AcquireSRWLockExclusive(&g_lock);
    if (g_present) {
        std::memcpy(body.data(), g_body.data(), g_body.size());
        bitCount = g_bitCount;
        g_present = false;
        g_bitCount = 0;
        taken = true;
    }
    ReleaseSRWLockExclusive(&g_lock);
    return taken;
}

} // namespace sunrise::server::gameplay::peer
