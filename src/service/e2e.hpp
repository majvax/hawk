#pragma once

#include "common/input_pipe.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "machine_key.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// End-to-end encryption, the machine's side. The relay passes everything
// between this machine and its viewers' browsers but is trusted with none
// of it: the machine decides who may watch from its owner's signatures,
// checked against the owner key it pinned at enrollment, and every viewer
// gets a key exchange signed by the machine's own key (see
// frontend/src/e2e.ts for the browser's side and relay/src/e2e.rs for the
// statement format).
namespace hawk::service {

// --- Enrollment --------------------------------------------------------------

// What the relay is told about the enrollment code: base64 SHA-256 of its
// canonical form. The code itself never leaves the machine.
[[nodiscard]] std::string enroll_code_hash(std::string_view code);

// HMAC of `public_key` under a key derived from the code, with `context`
// saying whose key it is ("hawk-enroll-owner-v1", "hawk-enroll-machine-v1").
[[nodiscard]] crypto::Sha256Digest enroll_binding(std::string_view code, std::string_view context,
                                                  std::span<const std::byte> public_key);

// "AB12 CD34 ...": the first 16 bytes of SHA-256(public_key), as the
// dashboard shows it, for the owner to compare.
[[nodiscard]] std::string fingerprint(std::span<const std::byte> public_key);

// The owner's identity key, pinned at enrollment once its binding checked
// out; C:\ProgramData\HawkService\owner-key.txt.
[[nodiscard]] std::optional<crypto::Bytes> load_owner_key();
[[nodiscard]] bool                         save_owner_key(std::span<const std::byte> key);

// A statement and its signature, as the relay passes them on.
struct SignedStatement {
    std::string statement;
    std::string signature;  // base64 r || s
};

// --- Viewers -------------------------------------------------------------------

// What a viewer asked of the machine's clipboard, once ViewerHub checked
// that its role and the machine's config allow it.
struct ClipboardRequest {
    enum class Op : std::uint8_t { set, get };
    Op          op = Op::get;
    std::string text;  // set: valid UTF-8, within the configured max_size
};

// One message of the file or shell channel, either way, once opened: what
// it is, a JSON header saying which transfer or shell and where, and bytes
// (file data, terminal input or output). See files.hpp and shell.hpp for
// the ops.
struct ChannelMessage {
    std::uint8_t  op = 0;
    std::string   header;
    crypto::Bytes data;
};

// Every viewer of this machine on the current relay connection: who the
// owner's signatures let in, each one's session keys, the stream key the
// frames are sealed with, and what each one's input is holding down.
//
// Thread-safety: seal_frame() and check_expiry() run on the capture
// thread, the rest on the relay thread; all of it is serialized inside.
// Messages for the relay go out through `send`, under the same lock, so a
// new stream key always reaches viewers before the first frame under it.
class ViewerHub {
public:
    using Sender = std::function<void(const std::string&)>;

    // `owner_key` is empty for a machine enrolled before end-to-end
    // encryption, which refuses every viewer until it's enrolled again.
    ViewerHub(const MachineKey& key, std::string machine_id, std::optional<crypto::Bytes> owner_key,
              const MachineConfig& config, Sender send);
    ~ViewerHub();
    ViewerHub(const ViewerHub&) = delete;
    ViewerHub& operator=(const ViewerHub&) = delete;
    ViewerHub(ViewerHub&&) = delete;
    ViewerHub& operator=(ViewerHub&&) = delete;

    // A viewer's signed join request and its grant: answers with a
    // viewer_accept (and the stream key) or a viewer_reject.
    void join(std::uint64_t viewer, const SignedStatement& request, const std::optional<SignedStatement>& grant);

    // The viewer stopped watching (or was refused): moves everyone else to
    // a new stream key, and returns what lets go of its input.
    [[nodiscard]] std::vector<ipc::InputPacket> leave(std::uint64_t viewer);

    // Opens one sealed input event; returns it, ready for hawk-capture, if
    // it's genuine, new, and from a viewer whose role allows control.
    [[nodiscard]] std::optional<ipc::InputPacket> input(std::uint64_t viewer, std::string_view sealed);

    // Opens one sealed clipboard request; returns it if it's genuine, new,
    // and allowed: setting needs control, reading needs control or the
    // config's view_pull, and neither works with the clipboard off. A get
    // is remembered, and answered by the next deliver_clipboard().
    [[nodiscard]] std::optional<ClipboardRequest> clipboard(std::uint64_t viewer, std::string_view sealed);

    // Text read off the machine's clipboard, sealed for each viewer it's
    // for: those waiting on a get, or with `pushed` (a copy on the machine,
    // sync mode only) everyone allowed to read it. Truncated to max_size.
    void deliver_clipboard(std::string_view text, bool pushed);

    // Opens one sealed file-channel message; returns it if it's genuine,
    // new, and from a viewer with control while file transfer is on.
    [[nodiscard]] std::optional<ChannelMessage> file(std::uint64_t viewer, std::string_view sealed);

    // Seals a file-channel message for one viewer and sends it. False when
    // that viewer is gone, refused, or no longer allowed files.
    bool send_file(std::uint64_t viewer, const ChannelMessage& message);

    // The same for the shell channel: owner and dev viewers only, while the
    // config has the shell on.
    [[nodiscard]] std::optional<ChannelMessage> shell(std::uint64_t viewer, std::string_view sealed);
    bool send_shell(std::uint64_t viewer, const ChannelMessage& message);

    // The same for the metrics channel (metrics.hpp): the owner, and viewers
    // whose grant says analytics=1, while the config has metrics on.
    [[nodiscard]] std::optional<ChannelMessage> metrics(std::uint64_t viewer, std::string_view sealed);
    bool send_metrics(std::uint64_t viewer, const ChannelMessage& message);

    // "AB12 CD34 ..." for the viewer's identity key, for the log; empty
    // for a viewer that isn't here.
    [[nodiscard]] std::string fingerprint_of(std::uint64_t viewer);

    // Every revocation the owner has signed: remembered, and any viewer
    // they cut off is refused on the spot.
    void apply_revocations(const std::vector<SignedStatement>& revocations);

    // Refuses viewers whose grant has run out. Cheap; call it often.
    void check_expiry();

    // One encoded frame, sealed under the current stream key, in the
    // binary layout the relay forwards.
    [[nodiscard]] crypto::Bytes seal_frame(std::span<const std::byte> access_unit, bool keyframe,
                                           std::chrono::microseconds timestamp);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
