#pragma once

#include "common/clipboard_pipe.hpp"

#include <cstdint>

// The machine's own settings, from C:\ProgramData\HawkService\config.toml.
// They're set on the machine, never through the relay, so nobody holding an
// account there can widen what the machine allows. Read once at startup.
namespace hawk::service {

// What viewers may do with the machine's clipboard.
enum class ClipboardMode : std::uint8_t {
    off,   // nothing, in either direction
    pull,  // paste into the machine; read it only when a viewer asks
    sync,  // pull, plus every copy on the machine is pushed to viewers
};

struct ClipboardConfig {
    ClipboardMode mode = ClipboardMode::pull;
    // Most UTF-8 bytes of text taken or sent at once; capped at
    // ipc::max_clipboard_size.
    std::uint32_t max_size = ipc::max_clipboard_size;
    // Whether view-only shares may read the clipboard too. Pasting into the
    // machine always needs control.
    bool view_pull = false;
};

struct MachineConfig {
    ClipboardConfig clipboard;
};

// The config, with defaults for what it leaves out (or for a missing file).
// A file that doesn't parse, or says something that makes no sense, is
// logged and turns the clipboard off: a typo should never open up more
// than the defaults would.
//
//   [[clipboard]]
//   mode = "pull"        # off | pull | sync
//   max_size = 262144    # bytes, at most 262144
//   view_pull = false
[[nodiscard]] MachineConfig load_machine_config();

}  // namespace hawk::service
