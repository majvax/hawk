#include "input.hpp"

#include "common/input_pipe.hpp"
#include "desktop.hpp"

#include <windows.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <thread>
#include <vector>

namespace hawk::capture {

namespace {

// One physical key: the name the browser gives it, and the PS/2 set 1
// scancode a keyboard would send for it.
struct KeyMapping {
    std::string_view code;      // KeyboardEvent.code
    std::uint16_t    scancode;  // PS/2 set 1
    bool             extended;  // the E0-prefixed half of the set
};

// Keys are injected as scancodes (KEYEVENTF_SCANCODE), not virtual keys, so
// the machine applies its own keyboard layout exactly as it would to a
// keyboard plugged into it: `KeyboardEvent.code` already names the physical
// key rather than the character on it, and games that read scancodes see
// what they expect. Keys this table doesn't name are dropped.
//
// Power, Sleep and WakeUp are deliberately absent: injecting one would end
// the session the viewer is working in.
constexpr auto key_mappings = std::to_array<KeyMapping>({
    // Row 1.
    {"Escape", 0x01, false},
    {"F1", 0x3B, false},
    {"F2", 0x3C, false},
    {"F3", 0x3D, false},
    {"F4", 0x3E, false},
    {"F5", 0x3F, false},
    {"F6", 0x40, false},
    {"F7", 0x41, false},
    {"F8", 0x42, false},
    {"F9", 0x43, false},
    {"F10", 0x44, false},
    {"F11", 0x57, false},
    {"F12", 0x58, false},
    {"PrintScreen", 0x37, true},
    {"ScrollLock", 0x46, false},
    // Digits and the punctuation around them.
    {"Backquote", 0x29, false},
    {"Digit1", 0x02, false},
    {"Digit2", 0x03, false},
    {"Digit3", 0x04, false},
    {"Digit4", 0x05, false},
    {"Digit5", 0x06, false},
    {"Digit6", 0x07, false},
    {"Digit7", 0x08, false},
    {"Digit8", 0x09, false},
    {"Digit9", 0x0A, false},
    {"Digit0", 0x0B, false},
    {"Minus", 0x0C, false},
    {"Equal", 0x0D, false},
    {"Backspace", 0x0E, false},
    // Letters, by their position on a US keyboard.
    {"Tab", 0x0F, false},
    {"KeyQ", 0x10, false},
    {"KeyW", 0x11, false},
    {"KeyE", 0x12, false},
    {"KeyR", 0x13, false},
    {"KeyT", 0x14, false},
    {"KeyY", 0x15, false},
    {"KeyU", 0x16, false},
    {"KeyI", 0x17, false},
    {"KeyO", 0x18, false},
    {"KeyP", 0x19, false},
    {"BracketLeft", 0x1A, false},
    {"BracketRight", 0x1B, false},
    {"Enter", 0x1C, false},
    {"CapsLock", 0x3A, false},
    {"KeyA", 0x1E, false},
    {"KeyS", 0x1F, false},
    {"KeyD", 0x20, false},
    {"KeyF", 0x21, false},
    {"KeyG", 0x22, false},
    {"KeyH", 0x23, false},
    {"KeyJ", 0x24, false},
    {"KeyK", 0x25, false},
    {"KeyL", 0x26, false},
    {"Semicolon", 0x27, false},
    {"Quote", 0x28, false},
    {"Backslash", 0x2B, false},
    {"ShiftLeft", 0x2A, false},
    {"IntlBackslash", 0x56, false},
    {"KeyZ", 0x2C, false},
    {"KeyX", 0x2D, false},
    {"KeyC", 0x2E, false},
    {"KeyV", 0x2F, false},
    {"KeyB", 0x30, false},
    {"KeyN", 0x31, false},
    {"KeyM", 0x32, false},
    {"Comma", 0x33, false},
    {"Period", 0x34, false},
    {"Slash", 0x35, false},
    {"ShiftRight", 0x36, false},
    // Modifiers and the space bar.
    {"ControlLeft", 0x1D, false},
    {"MetaLeft", 0x5B, true},
    {"AltLeft", 0x38, false},
    {"Space", 0x39, false},
    {"AltRight", 0x38, true},
    {"MetaRight", 0x5C, true},
    {"ContextMenu", 0x5D, true},
    {"ControlRight", 0x1D, true},
    // Navigation block.
    {"Insert", 0x52, true},
    {"Delete", 0x53, true},
    {"Home", 0x47, true},
    {"End", 0x4F, true},
    {"PageUp", 0x49, true},
    {"PageDown", 0x51, true},
    {"ArrowUp", 0x48, true},
    {"ArrowDown", 0x50, true},
    {"ArrowLeft", 0x4B, true},
    {"ArrowRight", 0x4D, true},
    // Numeric keypad.
    {"NumLock", 0x45, false},
    {"NumpadDivide", 0x35, true},
    {"NumpadMultiply", 0x37, false},
    {"NumpadSubtract", 0x4A, false},
    {"NumpadAdd", 0x4E, false},
    {"NumpadEnter", 0x1C, true},
    {"NumpadDecimal", 0x53, false},
    {"Numpad0", 0x52, false},
    {"Numpad1", 0x4F, false},
    {"Numpad2", 0x50, false},
    {"Numpad3", 0x51, false},
    {"Numpad4", 0x4B, false},
    {"Numpad5", 0x4C, false},
    {"Numpad6", 0x4D, false},
    {"Numpad7", 0x47, false},
    {"Numpad8", 0x48, false},
    {"Numpad9", 0x49, false},
    // Extra function keys, as macro keyboards and remote desktops emit them.
    {"F13", 0x64, false},
    {"F14", 0x65, false},
    {"F15", 0x66, false},
    {"F16", 0x67, false},
    {"F17", 0x68, false},
    {"F18", 0x69, false},
    {"F19", 0x6A, false},
    {"F20", 0x6B, false},
    {"F21", 0x6C, false},
    {"F22", 0x6D, false},
    {"F23", 0x6E, false},
    {"F24", 0x76, false},
    // Keys only some layouts have (Japanese, Brazilian).
    {"IntlRo", 0x73, false},
    {"IntlYen", 0x7D, false},
    {"KanaMode", 0x70, false},
    {"Convert", 0x79, false},
    {"NonConvert", 0x7B, false},
    // Media and browser keys.
    {"AudioVolumeMute", 0x20, true},
    {"AudioVolumeDown", 0x2E, true},
    {"AudioVolumeUp", 0x30, true},
    {"MediaPlayPause", 0x22, true},
    {"MediaStop", 0x24, true},
    {"MediaTrackPrevious", 0x10, true},
    {"MediaTrackNext", 0x19, true},
    {"MediaSelect", 0x6D, true},
    {"LaunchMail", 0x6C, true},
    {"LaunchApp1", 0x6B, true},
    {"LaunchApp2", 0x21, true},
    {"BrowserHome", 0x32, true},
    {"BrowserSearch", 0x65, true},
    {"BrowserFavorites", 0x66, true},
    {"BrowserRefresh", 0x67, true},
    {"BrowserStop", 0x68, true},
    {"BrowserForward", 0x69, true},
    {"BrowserBack", 0x6A, true},
});

[[nodiscard]] const KeyMapping* find_key(std::string_view code) {
    for (const KeyMapping& mapping : key_mappings) {
        if (mapping.code == code) {
            return &mapping;
        }
    }
    return nullptr;
}

// Indexed by the order of ipc::InputButton.
constexpr std::array<DWORD, 3> button_down_flags{MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_MIDDLEDOWN};
constexpr std::array<DWORD, 3> button_up_flags{MOUSEEVENTF_LEFTUP, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_MIDDLEUP};

[[nodiscard]] std::optional<std::size_t> button_index(std::uint8_t button) {
    switch (static_cast<ipc::InputButton>(button)) {
        case ipc::InputButton::left:
            return 0;
        case ipc::InputButton::right:
            return 1;
        case ipc::InputButton::middle:
            return 2;
    }
    return std::nullopt;
}

// Replays input events with SendInput, remembering what it has pressed so it
// can let go of all of it on demand.
class Injector {
public:
    explicit Injector(DesktopBounds bounds) : bounds_(bounds) {}
    ~Injector() { release_all(); }

    Injector(const Injector&) = delete;
    Injector& operator=(const Injector&) = delete;
    Injector(Injector&&) = delete;
    Injector& operator=(Injector&&) = delete;

    void apply(const ipc::InputPacket& packet) {
        switch (static_cast<ipc::InputKind>(packet.kind)) {
            case ipc::InputKind::mouse_move:
                move(packet.x, packet.y);
                break;
            case ipc::InputKind::mouse_button:
                press_button(packet.button, packet.down != 0);
                break;
            case ipc::InputKind::wheel:
                wheel(packet.wheel_dx, packet.wheel_dy);
                break;
            case ipc::InputKind::key:
                press_key(packet);
                break;
            case ipc::InputKind::release_all:
                release_all();
                break;
            default:
                spdlog::warn("input: ignoring event of unknown kind {}", packet.kind);
                break;
        }
    }

    // Sends an "up" for every key and button still down. Called when the
    // viewer lets go of the machine, and on the way out.
    void release_all() {
        for (const KeyMapping* mapping : keys_held_) {
            send_key(*mapping, false);
        }
        keys_held_.clear();
        for (std::size_t index = 0; index < buttons_held_.size(); ++index) {
            if (buttons_held_.at(index)) {
                send_mouse(button_up_flags.at(index), 0);
            }
        }
        buttons_held_.fill(false);
    }

private:
    static void send(INPUT& input) {
        if (SendInput(1, &input, sizeof(INPUT)) != 1) {
            // UIPI blocks injection into a window of higher integrity than
            // this process unless it runs with uiAccess (see
            // capture/input.hpp); a lock screen or the secure desktop
            // refuses it either way.
            spdlog::warn("input: SendInput failed: Win32 error {}", GetLastError());
        }
    }

    static void send_mouse(DWORD flags, DWORD data, LONG x = 0, LONG y = 0) {
        INPUT input{};
        input.type = INPUT_MOUSE;
        input.mi.dx = x;
        input.mi.dy = y;
        input.mi.mouseData = data;
        input.mi.dwFlags = flags;
        send(input);
    }

    static void send_key(const KeyMapping& mapping, bool down) {
        INPUT input{};
        input.type = INPUT_KEYBOARD;
        input.ki.wScan = mapping.scancode;
        input.ki.dwFlags = KEYEVENTF_SCANCODE;
        if (mapping.extended) {
            input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
        }
        if (!down) {
            input.ki.dwFlags |= KEYEVENTF_KEYUP;
        }
        send(input);
    }

    // `x` and `y` are a fraction of the captured monitor, which picks out
    // one of its pixels. Absolute mouse input, on the other hand, is
    // 0..65535 across the whole virtual desktop (that's what
    // MOUSEEVENTF_VIRTUALDESK selects), so the monitor's own offset on that
    // desktop goes in here. The metrics are read per event rather than
    // cached: a monitor can be added, removed or moved while someone is
    // watching.
    //
    // 16 bits don't divide evenly into desktop pixels, and Windows' own
    // rounding of them lands up to a pixel away from the one asked for —
    // at the right edge of a monitor, far enough to spill onto the next
    // one. So the move goes in as real mouse input, which is what windows
    // and games watch for, and SetCursorPos then puts the cursor exactly on
    // the pixel the viewer pointed at.
    //
    // This assumes the captured monitor isn't rotated; on a rotated display
    // the duplicated frames are rotated too, which the encoder would have to
    // deal with first.
    void move(double x, double y) const {
        const auto width = std::max(1, bounds_.right - bounds_.left);
        const auto height = std::max(1, bounds_.bottom - bounds_.top);
        const auto pixel_x = bounds_.left + std::lround(std::clamp(x, 0.0, 1.0) * (width - 1));
        const auto pixel_y = bounds_.top + std::lround(std::clamp(y, 0.0, 1.0) * (height - 1));

        const auto virtual_left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        const auto virtual_top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        const auto virtual_width = std::max(2, GetSystemMetrics(SM_CXVIRTUALSCREEN));
        const auto virtual_height = std::max(2, GetSystemMetrics(SM_CYVIRTUALSCREEN));

        const auto dx = std::lround(static_cast<double>(pixel_x - virtual_left) * 65535.0 / (virtual_width - 1));
        const auto dy = std::lround(static_cast<double>(pixel_y - virtual_top) * 65535.0 / (virtual_height - 1));
        send_mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK, 0, static_cast<LONG>(dx),
                   static_cast<LONG>(dy));
        // Fails only when this thread isn't on the input desktop, where the
        // move above went nowhere either.
        static_cast<void>(SetCursorPos(static_cast<int>(pixel_x), static_cast<int>(pixel_y)));
    }

    void press_button(std::uint8_t button, bool down) {
        const auto index = button_index(button);
        if (!index.has_value()) {
            spdlog::warn("input: ignoring unknown mouse button {}", button);
            return;
        }
        // A button that's already in the requested state means a lost or
        // duplicated event; sending it again would only confuse whatever is
        // tracking drags on the machine.
        if (buttons_held_.at(*index) == down) {
            return;
        }
        buttons_held_.at(*index) = down;
        send_mouse(down ? button_down_flags.at(*index) : button_up_flags.at(*index), 0);
    }

    static void wheel(std::int32_t dx, std::int32_t dy) {
        if (dy != 0) {
            send_mouse(MOUSEEVENTF_WHEEL, static_cast<DWORD>(dy));
        }
        if (dx != 0) {
            send_mouse(MOUSEEVENTF_HWHEEL, static_cast<DWORD>(dx));
        }
    }

    void press_key(const ipc::InputPacket& packet) {
        // hawk-service terminates the name; stay inside the array even if a
        // packet ever doesn't.
        const auto* terminator = std::ranges::find(packet.code, '\0');
        const std::string_view code(packet.code.data(),
                                    static_cast<std::size_t>(terminator - packet.code.begin()));
        const KeyMapping* mapping = find_key(code);
        if (mapping == nullptr) {
            spdlog::debug("input: no key named \"{}\"", code);
            return;
        }

        const bool down = packet.down != 0;
        // Repeats are passed through as they come: holding a key down is
        // how text repeats, so only the held set is deduplicated.
        send_key(*mapping, down);
        if (down) {
            if (std::ranges::find(keys_held_, mapping) == keys_held_.end()) {
                keys_held_.push_back(mapping);
            }
        } else {
            std::erase(keys_held_, mapping);
        }
    }

    DesktopBounds                  bounds_;
    std::vector<const KeyMapping*> keys_held_;  // into key_mappings, which is static
    std::array<bool, 3>            buttons_held_{};
};

}  // namespace

struct InputChannel::Impl {
    HANDLE       pipe = INVALID_HANDLE_VALUE;
    HANDLE       io_event = nullptr;    // manual-reset; the read's OVERLAPPED event
    HANDLE       stop_event = nullptr;  // manual-reset; set by close()
    std::jthread reader;

    ~Impl() { close(); }

    void close() noexcept {
        if (stop_event != nullptr) {
            SetEvent(stop_event);
        }
        if (reader.joinable()) {
            reader.join();
        }
        for (HANDLE* handle : {&io_event, &stop_event}) {
            if (*handle != nullptr) {
                CloseHandle(*handle);
                *handle = nullptr;
            }
        }
        if (pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
        }
    }

    // Reads whole packets until hawk-service closes the pipe, close() is
    // called, or something goes wrong. The injector goes out of scope first,
    // which releases anything still held; then the pipe is closed, so that
    // hawk-service's next write fails at once rather than filling the pipe
    // and waiting on a reader that is gone.
    void read_events(DesktopBounds bounds) {
        {
            Injector injector(bounds);
            pump(injector);
        }
        CloseHandle(pipe);
        pipe = INVALID_HANDLE_VALUE;  // close() joins this thread before it looks
    }

    void pump(Injector& injector) {
        // SendInput goes to the desktop the calling thread is on, so this
        // thread follows the input desktop just as the capture loop does —
        // otherwise a click meant for the UAC prompt would land on the empty
        // normal desktop behind it. Re-checked per event: events are rare
        // next to the per-event cost, and a switch carries no other signal.
        HDESK input_desktop = nullptr;
        for (;;) {
            ipc::InputPacket packet{};
            const DWORD      result = read_exact(std::as_writable_bytes(std::span(&packet, 1)));
            if (result != NO_ERROR) {
                if (result == ERROR_BROKEN_PIPE) {
                    spdlog::info("input: hawk-service closed the input pipe");
                } else if (result != ERROR_OPERATION_ABORTED) {
                    spdlog::error("input: reading from hawk-service failed: Win32 error {}", result);
                }
                break;
            }
            if (packet.magic != ipc::input_packet_magic) {
                spdlog::error("input: malformed packet from hawk-service, dropping input");
                break;
            }
            static_cast<void>(follow_input_desktop(input_desktop));
            injector.apply(packet);
        }
        close_desktop(input_desktop);
    }

    [[nodiscard]] DWORD read_exact(std::span<std::byte> out) {
        std::size_t done = 0;
        while (done < out.size()) {
            OVERLAPPED overlapped{};
            overlapped.hEvent = io_event;
            ResetEvent(io_event);

            DWORD transferred = 0;
            if (ReadFile(pipe, out.subspan(done).data(), static_cast<DWORD>(out.size() - done), nullptr,
                         &overlapped) != FALSE) {
                GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
            } else if (const DWORD error = GetLastError(); error != ERROR_IO_PENDING) {
                return error;
            } else {
                const std::array<HANDLE, 2> waits{io_event, stop_event};
                const DWORD                 wait =
                    WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(), FALSE, INFINITE);
                if (wait != WAIT_OBJECT_0) {
                    // close(); cancel the read and wait it out so
                    // `overlapped` is never left in use on a dead stack.
                    CancelIoEx(pipe, &overlapped);
                    GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
                    return ERROR_OPERATION_ABORTED;
                }
                if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) == FALSE) {
                    return GetLastError();
                }
            }
            if (transferred == 0) {
                return ERROR_BROKEN_PIPE;
            }
            done += transferred;
        }
        return NO_ERROR;
    }
};

InputChannel::InputChannel() : impl_(std::make_unique<Impl>()) {}

InputChannel::~InputChannel() = default;

bool InputChannel::open(const std::string& pipe_name, DesktopBounds bounds) {
    // Not GENERIC_READ: that also asks for FILE_READ_EA and READ_CONTROL,
    // and hawk-service's DACL grants us only what reading actually needs
    // (see input_client_access in service/capture_host.cpp).
    constexpr DWORD access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    impl_->pipe = CreateFileA(pipe_name.c_str(), access, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (impl_->pipe == INVALID_HANDLE_VALUE) {
        spdlog::error("input: failed to open pipe {}: Win32 error {}", pipe_name, GetLastError());
        return false;
    }

    impl_->io_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    impl_->stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (impl_->io_event == nullptr || impl_->stop_event == nullptr) {
        spdlog::error("input: CreateEventW failed: Win32 error {}", GetLastError());
        impl_->close();
        return false;
    }

    impl_->reader = std::jthread([impl = impl_.get(), bounds] { impl->read_events(bounds); });
    spdlog::info("input: listening for input from hawk-service");
    return true;
}

void InputChannel::close() noexcept {
    impl_->close();
}

}  // namespace hawk::capture
