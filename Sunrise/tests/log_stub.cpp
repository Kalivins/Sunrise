// Link-time stub for the standalone encounter test.
//
// The logical WorldRunner (and its host layer) now emit diagnostic log lines through
// sunrise::core::log::write. The standalone test links only the world/ and encounter/ translation
// units, not the real logging subsystem (file sink, settings, channels), so that symbol would be
// unresolved. This no-op definition satisfies the linker without pulling those dependencies in.
// The test asserts on WorldRunner state directly, so dropping the log text costs it nothing.

#include "core/logging/log.h"

namespace sunrise::core::log {

void write(Channel /*channel*/, Level /*level*/, std::string_view /*event*/) noexcept {}

} // namespace sunrise::core::log
