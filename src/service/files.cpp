#include "files.hpp"

#include "win_util.hpp"

#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <glaze/glaze.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cwctype>
#include <deque>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace hawk::service {

namespace {

using win::Impersonation;
using win::UniqueHandle;
using win::to_utf8;
using win::to_wide;
using win::user_token;

// What one chunk carries, and how many may be unacknowledged at once:
// half a megabyte in flight per transfer, whatever the link.
constexpr std::size_t kChunkSize = 64 * 1024;
constexpr std::size_t kWindowChunks = 8;
// Transfers one viewer may have going each way, and the machine overall.
constexpr std::size_t kMaxPerViewer = 2;
constexpr std::size_t kMaxTransfers = 6;
// A download whose viewer stopped acknowledging is given up on; an upload
// whose viewer stopped sending is closed (its partial file stays).
constexpr auto kDownloadTimeout = std::chrono::seconds(20);
constexpr auto kUploadTimeout = std::chrono::minutes(2);
// Partial files nobody came back for are cleaned up when the directory is
// next listed.
constexpr auto kStalePartial = std::chrono::hours(24 * 7);
// The listing has to fit one message header.
constexpr std::size_t kMaxListingBytes = 60 * 1024;
constexpr std::size_t kMaxListed = 1000;
// Room for a name and its " (999)" suffix within MAX_PATH-ish limits.
constexpr std::size_t kMaxNameLength = 200;
constexpr std::size_t kMaxIdLength = 40;

constexpr std::wstring_view kPartialPrefix = L".hawk-";
constexpr std::wstring_view kPartialSuffix = L".part";

using Clock = std::chrono::steady_clock;

[[nodiscard]] std::string hex(std::span<const std::byte> bytes) {
    std::string text;
    for (const auto byte : bytes) {
        text += std::format("{:02x}", std::to_integer<unsigned>(byte));
    }
    return text;
}

[[nodiscard]] bool is_reserved_device(std::wstring_view name) {
    auto stem = name.substr(0, name.find(L'.'));
    while (!stem.empty() && stem.back() == L' ') {
        stem.remove_suffix(1);
    }
    std::wstring upper(stem);
    std::ranges::transform(upper, upper.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
    for (const std::wstring_view reserved : {L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$"}) {
        if (upper == reserved) {
            return true;
        }
    }
    return upper.size() == 4 && (upper.starts_with(L"COM") || upper.starts_with(L"LPT")) && upper[3] >= L'0' &&
           upper[3] <= L'9';
}

// A name that can only ever mean a file in the drop directory itself: the
// last path component, with whatever Windows reserves replaced, never a
// device and never one of our partial files. nullopt for text that isn't
// UTF-8.
[[nodiscard]] std::optional<std::wstring> sanitize_name(std::string_view utf8) {
    auto wide = to_wide(utf8);
    if (!wide.has_value()) {
        return std::nullopt;
    }
    std::wstring name = *wide;
    if (const auto slash = name.find_last_of(L"/\\"); slash != std::wstring::npos) {
        name.erase(0, slash + 1);
    }
    for (auto& c : name) {
        if (c < 0x20 || std::wstring_view(L"<>:\"/\\|?*").find(c) != std::wstring_view::npos) {
            c = L'_';
        }
    }
    while (!name.empty() && (name.back() == L' ' || name.back() == L'.')) {
        name.pop_back();
    }
    while (!name.empty() && name.front() == L' ') {
        name.erase(0, 1);
    }
    if (name.empty()) {
        name = L"file";
    }
    if (is_reserved_device(name) || name.starts_with(kPartialPrefix)) {
        name.insert(0, 1, L'_');
    }
    if (name.size() > kMaxNameLength) {
        const auto dot = name.rfind(L'.');
        const bool keep_extension = dot != std::wstring::npos && name.size() - dot <= 16;
        const std::wstring extension = keep_extension ? name.substr(dot) : std::wstring{};
        name = name.substr(0, kMaxNameLength - extension.size()) + extension;
    }
    return name;
}

[[nodiscard]] bool is_valid_id(std::string_view id) {
    return !id.empty() && id.size() <= kMaxIdLength && std::ranges::all_of(id, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
    });
}

[[nodiscard]] bool exists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// "name.ext", or "name (1).ext", "name (2).ext"... whichever is free.
[[nodiscard]] std::optional<std::wstring> free_name(const std::wstring& dir, const std::wstring& name) {
    if (!exists(dir + L"\\" + name)) {
        return name;
    }
    const auto dot = name.rfind(L'.');
    const auto stem = dot == std::wstring::npos || dot == 0 ? name : name.substr(0, dot);
    const auto extension = dot == std::wstring::npos || dot == 0 ? std::wstring{} : name.substr(dot);
    for (int n = 1; n < 1000; ++n) {
        auto candidate = std::format(L"{} ({}){}", stem, n, extension);
        if (!exists(dir + L"\\" + candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::uint64_t file_time_to_unix(FILETIME time) {
    const auto ticks = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime;
    constexpr std::uint64_t kEpochDifference = 116444736000000000ULL;  // 1601 -> 1970, in 100 ns
    return ticks < kEpochDifference ? 0 : (ticks - kEpochDifference) / 10000000ULL;
}

// SHA-256 of a file from its start, leaving the position at `then`.
[[nodiscard]] std::optional<crypto::Sha256Digest> hash_file(HANDLE file, std::uint64_t then) {
    LARGE_INTEGER zero{};
    if (SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) == FALSE) {
        return std::nullopt;
    }
    crypto::Sha256Stream   hash;
    std::vector<std::byte> buffer(1024 * 1024);
    for (;;) {
        DWORD read = 0;
        if (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) == FALSE) {
            return std::nullopt;
        }
        if (read == 0) {
            break;
        }
        hash.update(std::span(buffer).first(read));
    }
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(then);
    if (SetFilePointerEx(file, position, nullptr, FILE_BEGIN) == FALSE) {
        return std::nullopt;
    }
    return hash.finish();
}

[[nodiscard]] bool write_all(HANDLE file, std::span<const std::byte> data) {
    while (!data.empty()) {
        DWORD written = 0;
        if (WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) == FALSE || written == 0) {
            return false;
        }
        data = data.subspan(written);
    }
    return true;
}

// --- message headers ---------------------------------------------------------

struct RequestHeader {
    std::string   id;
    std::string   name;
    std::uint64_t size = 0;
    std::string   sha256;  // base64
    std::uint64_t offset = 0;
    std::uint64_t received = 0;
};

struct ReplyHeader {
    std::string                  id;
    std::optional<std::uint64_t> offset;
    std::optional<std::uint64_t> received;
    std::optional<std::uint64_t> size;
    std::optional<std::string>   name;
    std::optional<std::string>   sha256;
    std::optional<std::string>   message;
};

struct ListedFile {
    std::string   name;
    std::uint64_t size = 0;
    std::uint64_t modified = 0;  // unix seconds
};

struct Listing {
    std::string             dir;
    std::vector<ListedFile> files;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::RequestHeader> {
    using T                     = hawk::service::RequestHeader;
    static constexpr auto value = object("id", &T::id, "name", &T::name, "size", &T::size, "sha256", &T::sha256,
                                         "offset", &T::offset, "received", &T::received);
};

template <>
struct glz::meta<hawk::service::ReplyHeader> {
    using T                     = hawk::service::ReplyHeader;
    static constexpr auto value = object("id", &T::id, "offset", &T::offset, "received", &T::received, "size",
                                         &T::size, "name", &T::name, "sha256", &T::sha256, "message", &T::message);
};

template <>
struct glz::meta<hawk::service::ListedFile> {
    using T                     = hawk::service::ListedFile;
    static constexpr auto value = object("name", &T::name, "size", &T::size, "modified", &T::modified);
};

template <>
struct glz::meta<hawk::service::Listing> {
    using T                     = hawk::service::Listing;
    static constexpr auto value = object("dir", &T::dir, "files", &T::files);
};

namespace hawk::service {

namespace {

template <typename Header>
[[nodiscard]] std::string to_json(const Header& header) {
    auto json = glz::write_json(header);
    return json.has_value() ? *json : std::string{};
}

// What a viewer is a transfer for, and its id.
using TransferKey = std::pair<std::uint64_t, std::string>;

struct Upload {
    std::wstring         dir;
    std::wstring         partial;
    std::wstring         name;
    std::uint64_t        size = 0;
    std::uint64_t        received = 0;
    crypto::Sha256Digest sha256{};
    UniqueHandle         file;
    Clock::time_point    last_activity = Clock::now();
};

struct Download {
    std::string       name;
    UniqueHandle      file;
    std::uint64_t     size = 0;
    std::uint64_t     sent = 0;
    std::uint64_t     acked = 0;
    Clock::time_point last_ack = Clock::now();
};

struct Request {
    std::uint64_t viewer = 0;
    ChannelMessage   message;
};

struct Drop {
    std::uint64_t viewer = 0;
};

}  // namespace

struct FileTransfers::Impl {
    FilesConfig config;
    ViewerHub&  hub;

    std::mutex                               mutex;
    std::condition_variable                  wake;
    std::deque<std::variant<Request, Drop>>  queue;
    bool                                     stopping = false;

    // Worker thread only.
    std::map<TransferKey, Upload>   uploads;
    std::map<TransferKey, Download> downloads;

    std::jthread worker;

    Impl(FilesConfig files, ViewerHub& viewer_hub) : config(std::move(files)), hub(viewer_hub) {
        worker = std::jthread([this] { run(); });
    }

    ~Impl() {
        {
            const std::lock_guard lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        worker.join();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    void push(std::variant<Request, Drop> event) {
        {
            const std::lock_guard lock(mutex);
            queue.push_back(std::move(event));
        }
        wake.notify_one();
    }

    void run() {
        for (;;) {
            std::deque<std::variant<Request, Drop>> events;
            {
                std::unique_lock lock(mutex);
                // Only an open download needs waking for: its window drains
                // as acks arrive, and those come through the queue.
                wake.wait_for(lock, std::chrono::milliseconds(500), [this] { return stopping || !queue.empty(); });
                if (stopping) {
                    break;
                }
                std::swap(events, queue);
            }
            for (auto& event : events) {
                if (auto* request = std::get_if<Request>(&event)) {
                    serve(request->viewer, request->message);
                } else {
                    forget_viewer(std::get<Drop>(event).viewer);
                }
            }
            pump();
            expire();
        }
        uploads.clear();
        downloads.clear();
    }

    // --- replies --------------------------------------------------------------

    void reply(std::uint64_t viewer, std::uint8_t op, const auto& header, std::span<const std::byte> data = {}) {
        ChannelMessage message{.op = op, .header = to_json(header), .data = {data.begin(), data.end()}};
        hub.send_file(viewer, message);
    }

    void fail(std::uint64_t viewer, const std::string& id, std::string message) {
        spdlog::info("files: viewer {} ({}): {}", viewer, hub.fingerprint_of(viewer), message);
        reply(viewer, file_op::error, ReplyHeader{.id = id, .message = std::move(message)});
    }

    // --- the user's side of things ---------------------------------------------

    // The drop directory, created if it isn't there. Resolved as the user:
    // their Downloads folder, or their environment in a configured path.
    [[nodiscard]] std::optional<std::wstring> drop_dir(HANDLE token) const {
        std::wstring dir;
        if (config.drop_dir.empty()) {
            PWSTR downloads = nullptr;
            if (FAILED(SHGetKnownFolderPath(FOLDERID_Downloads, KF_FLAG_DEFAULT, token, &downloads))) {
                return std::nullopt;
            }
            dir = std::wstring(downloads) + L"\\Hawk";
            CoTaskMemFree(downloads);
        } else {
            const auto configured = to_wide(config.drop_dir);
            if (!configured.has_value()) {
                return std::nullopt;
            }
            std::array<wchar_t, 32768> expanded{};
            if (ExpandEnvironmentStringsForUserW(token, configured->c_str(), expanded.data(),
                                                 static_cast<DWORD>(expanded.size())) == FALSE) {
                return std::nullopt;
            }
            dir = expanded.data();
        }
        while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) {
            dir.pop_back();
        }
        const Impersonation as_user(token);
        if (!as_user.ok()) {
            return std::nullopt;
        }
        if (CreateDirectoryW(dir.c_str(), nullptr) == FALSE && GetLastError() != ERROR_ALREADY_EXISTS) {
            return std::nullopt;
        }
        const DWORD attributes = GetFileAttributesW(dir.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            return std::nullopt;
        }
        return dir;
    }

    // Token and directory for one request, or a reply saying why not.
    [[nodiscard]] std::optional<std::pair<UniqueHandle, std::wstring>> user_and_dir(std::uint64_t viewer,
                                                                                     const std::string& id) {
        auto token = user_token();
        if (!token) {
            fail(viewer, id, "nobody is logged on to the machine");
            return std::nullopt;
        }
        auto dir = drop_dir(token.get());
        if (!dir.has_value()) {
            fail(viewer, id, "the machine's drop folder isn't available");
            return std::nullopt;
        }
        return std::pair{std::move(token), std::move(*dir)};
    }

    // --- requests ---------------------------------------------------------------

    void serve(std::uint64_t viewer, const ChannelMessage& message) {
        RequestHeader header;
        if (glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header)) {
            return;
        }
        if (message.op != file_op::list && !is_valid_id(header.id)) {
            return;
        }
        switch (message.op) {
            case file_op::list:
                list(viewer);
                break;
            case file_op::offer:
                offer(viewer, header);
                break;
            case file_op::chunk:
                chunk(viewer, header, message.data);
                break;
            case file_op::fetch:
                fetch(viewer, header);
                break;
            case file_op::ack:
                ack(viewer, header);
                break;
            case file_op::cancel:
                cancel(viewer, header.id);
                break;
            default:
                break;
        }
    }

    void list(std::uint64_t viewer) {
        auto context = user_and_dir(viewer, {});
        if (!context.has_value()) {
            return;
        }
        auto& [token, dir] = *context;
        const Impersonation as_user(token.get());
        if (!as_user.ok()) {
            fail(viewer, {}, "couldn't act as the logged-on user");
            return;
        }

        Listing          listing{.dir = to_utf8(dir), .files = {}};
        WIN32_FIND_DATAW found{};
        HANDLE search = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &found, FindExSearchNameMatch,
                                         nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (search != INVALID_HANDLE_VALUE) {
            const auto now = std::chrono::system_clock::now();
            do {
                const std::wstring_view name(found.cFileName);
                if ((found.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                    continue;
                }
                const auto modified = file_time_to_unix(found.ftLastWriteTime);
                if (name.starts_with(kPartialPrefix) && name.ends_with(kPartialSuffix)) {
                    const auto age = now - std::chrono::system_clock::time_point(std::chrono::seconds(modified));
                    if (age > kStalePartial) {
                        DeleteFileW((dir + L"\\" + std::wstring(name)).c_str());
                    }
                    continue;
                }
                if (listing.files.size() < kMaxListed) {
                    listing.files.push_back(ListedFile{
                        .name = to_utf8(name),
                        .size = (static_cast<std::uint64_t>(found.nFileSizeHigh) << 32U) | found.nFileSizeLow,
                        .modified = modified,
                    });
                }
            } while (FindNextFileW(search, &found) != FALSE);
            FindClose(search);
        }
        std::ranges::sort(listing.files, [](const auto& a, const auto& b) { return a.modified > b.modified; });
        auto json = to_json(listing);
        while (json.size() > kMaxListingBytes && !listing.files.empty()) {
            listing.files.resize(listing.files.size() * 3 / 4);
            json = to_json(listing);
        }
        hub.send_file(viewer, ChannelMessage{.op = file_op::listing, .header = std::move(json), .data = {}});
    }

    [[nodiscard]] std::size_t count_for(const auto& transfers, std::uint64_t viewer) const {
        return static_cast<std::size_t>(
            std::ranges::count_if(transfers, [viewer](const auto& entry) { return entry.first.first == viewer; }));
    }

    void offer(std::uint64_t viewer, const RequestHeader& header) {
        const TransferKey key{viewer, header.id};
        uploads.erase(key);  // offered again: start over from the partial file
        if (header.size > config.max_size) {
            fail(viewer, header.id, std::format("that's more than the {} bytes this machine takes", config.max_size));
            return;
        }
        const auto sha256 = crypto::base64_decode(header.sha256);
        auto       name = sanitize_name(header.name);
        if (!sha256.has_value() || sha256->size() != crypto::sha256_size || !name.has_value()) {
            fail(viewer, header.id, "malformed offer");
            return;
        }
        if (count_for(uploads, viewer) >= kMaxPerViewer || uploads.size() + downloads.size() >= kMaxTransfers) {
            fail(viewer, header.id, "too many transfers at once; wait for one to finish");
            return;
        }
        auto context = user_and_dir(viewer, header.id);
        if (!context.has_value()) {
            return;
        }
        auto& [token, dir] = *context;

        // Named by what's in it, so the same file offered again (after a
        // dropped connection, from another tab) finds what already arrived.
        crypto::Bytes identity(sha256->begin(), sha256->end());
        for (int shift = 56; shift >= 0; shift -= 8) {
            identity.push_back(static_cast<std::byte>((header.size >> shift) & 0xFFU));
        }
        const auto   identity_hash = crypto::sha256(identity);
        const auto   tag = hex(std::span(identity_hash).first(16));
        std::wstring partial = dir + L"\\" + std::wstring(kPartialPrefix) + std::wstring(tag.begin(), tag.end()) +
                               std::wstring(kPartialSuffix);
        if (std::ranges::any_of(uploads, [&](const auto& entry) { return entry.second.partial == partial; })) {
            fail(viewer, header.id, "this file is already being sent");
            return;
        }

        UniqueHandle file;
        {
            const Impersonation as_user(token.get());
            if (!as_user.ok()) {
                fail(viewer, header.id, "couldn't act as the logged-on user");
                return;
            }
            file.reset(CreateFileW(partial.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                   OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr));
        }
        if (!file) {
            fail(viewer, header.id, std::format("couldn't create the file (Win32 error {})", GetLastError()));
            return;
        }
        LARGE_INTEGER existing{};
        GetFileSizeEx(file.get(), &existing);
        auto offset = static_cast<std::uint64_t>(existing.QuadPart);
        if (offset > header.size) {
            offset = 0;
        }
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);
        if (SetFilePointerEx(file.get(), position, nullptr, FILE_BEGIN) == FALSE || SetEndOfFile(file.get()) == FALSE) {
            fail(viewer, header.id, "couldn't prepare the file");
            return;
        }

        Upload upload{.dir = dir,
                      .partial = std::move(partial),
                      .name = std::move(*name),
                      .size = header.size,
                      .received = offset,
                      .sha256 = {},
                      .file = std::move(file)};
        std::ranges::copy(*sha256, upload.sha256.begin());
        if (offset > 0) {
            spdlog::info("files: viewer {} ({}) resumes \"{}\" at {} of {} bytes", viewer, hub.fingerprint_of(viewer),
                         to_utf8(upload.name), offset, header.size);
        }
        auto& stored = uploads.insert_or_assign(key, std::move(upload)).first->second;
        reply(viewer, file_op::accepted, ReplyHeader{.id = header.id, .offset = offset});
        if (stored.received == stored.size) {
            finish_upload(key);
        }
    }

    void chunk(std::uint64_t viewer, const RequestHeader& header, std::span<const std::byte> data) {
        const TransferKey key{viewer, header.id};
        const auto        found = uploads.find(key);
        if (found == uploads.end()) {
            return;  // cancelled, or timed out: the viewer offers it again
        }
        Upload& upload = found->second;
        if (header.offset != upload.received || data.size() > kChunkSize || data.size() > upload.size - upload.received) {
            uploads.erase(found);
            fail(viewer, header.id, "a piece arrived out of place; send the file again to resume");
            return;
        }
        if (!write_all(upload.file.get(), data)) {
            uploads.erase(found);
            fail(viewer, header.id, std::format("writing the file failed (Win32 error {})", GetLastError()));
            return;
        }
        upload.received += data.size();
        upload.last_activity = Clock::now();
        reply(viewer, file_op::progress, ReplyHeader{.id = header.id, .received = upload.received});
        if (upload.received == upload.size) {
            finish_upload(key);
        }
    }

    // Everything arrived: check it's what was offered, and give it its name.
    void finish_upload(const TransferKey& key) {
        auto node = uploads.extract(key);
        if (node.empty()) {
            return;
        }
        const auto& [viewer, id] = key;
        Upload&     upload = node.mapped();
        const auto  digest = hash_file(upload.file.get(), upload.size);
        upload.file.reset();

        auto token = user_token();
        if (!token) {
            fail(viewer, id, "nobody is logged on to the machine");
            return;
        }
        const Impersonation as_user(token.get());
        if (!as_user.ok()) {
            fail(viewer, id, "couldn't act as the logged-on user");
            return;
        }
        if (!digest.has_value() || !crypto::equal(*digest, upload.sha256)) {
            DeleteFileW(upload.partial.c_str());
            fail(viewer, id, "the file didn't arrive intact; send it again");
            return;
        }
        const auto name = free_name(upload.dir, upload.name);
        if (!name.has_value() ||
            MoveFileExW(upload.partial.c_str(), (upload.dir + L"\\" + *name).c_str(), MOVEFILE_WRITE_THROUGH) == FALSE) {
            fail(viewer, id, std::format("couldn't save the file (Win32 error {})", GetLastError()));
            return;
        }
        SetFileAttributesW((upload.dir + L"\\" + *name).c_str(), FILE_ATTRIBUTE_NORMAL);
        spdlog::info("files: viewer {} ({}) sent \"{}\" ({} bytes, sha256 {})", viewer, hub.fingerprint_of(viewer),
                     to_utf8(*name), upload.size, hex(upload.sha256));
        reply(viewer, file_op::done, ReplyHeader{.id = id, .name = to_utf8(*name)});
    }

    void fetch(std::uint64_t viewer, const RequestHeader& header) {
        const TransferKey key{viewer, header.id};
        downloads.erase(key);  // asked again: start over from its offset
        // Only a name exactly as the listing gave it: nothing that could
        // reach out of the drop directory, and none of our partial files.
        const auto name = sanitize_name(header.name);
        if (!name.has_value() || to_utf8(*name) != header.name) {
            fail(viewer, header.id, "no such file");
            return;
        }
        if (count_for(downloads, viewer) >= kMaxPerViewer || uploads.size() + downloads.size() >= kMaxTransfers) {
            fail(viewer, header.id, "too many transfers at once; wait for one to finish");
            return;
        }
        auto context = user_and_dir(viewer, header.id);
        if (!context.has_value()) {
            return;
        }
        auto& [token, dir] = *context;
        UniqueHandle file;
        {
            const Impersonation as_user(token.get());
            if (!as_user.ok()) {
                fail(viewer, header.id, "couldn't act as the logged-on user");
                return;
            }
            file.reset(CreateFileW((dir + L"\\" + *name).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!file || GetFileInformationByHandle(file.get(), &info) == FALSE ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            fail(viewer, header.id, "no such file");
            return;
        }
        const auto size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32U) | info.nFileSizeLow;
        if (size > config.max_size) {
            fail(viewer, header.id, std::format("that's more than the {} bytes this machine sends", config.max_size));
            return;
        }
        if (header.offset > size) {
            fail(viewer, header.id, "the file changed since; download it again");
            return;
        }
        const auto digest = hash_file(file.get(), header.offset);
        if (!digest.has_value()) {
            fail(viewer, header.id, "couldn't read the file");
            return;
        }
        reply(viewer, file_op::meta,
              ReplyHeader{.id = header.id, .size = size, .sha256 = crypto::base64_encode(*digest)});
        if (header.offset == size) {
            log_download(viewer, header.name, size, *digest);
            return;
        }
        if (header.offset == 0) {
            log_download(viewer, header.name, size, *digest);
        }
        downloads.insert_or_assign(key, Download{.name = header.name,
                                                 .file = std::move(file),
                                                 .size = size,
                                                 .sent = header.offset,
                                                 .acked = header.offset,
                                                 .last_ack = Clock::now()});
    }

    void log_download(std::uint64_t viewer, const std::string& name, std::uint64_t size,
                      const crypto::Sha256Digest& digest) {
        spdlog::info("files: viewer {} ({}) fetches \"{}\" ({} bytes, sha256 {})", viewer, hub.fingerprint_of(viewer),
                     name, size, hex(digest));
    }

    void ack(std::uint64_t viewer, const RequestHeader& header) {
        const auto found = downloads.find(TransferKey{viewer, header.id});
        if (found == downloads.end()) {
            return;
        }
        Download& download = found->second;
        download.acked = std::clamp(header.received, download.acked, download.sent);
        download.last_ack = Clock::now();
        if (download.acked == download.size) {
            downloads.erase(found);
        }
    }

    void cancel(std::uint64_t viewer, const std::string& id) {
        const TransferKey key{viewer, id};
        if (auto node = uploads.extract(key); !node.empty()) {
            node.mapped().file.reset();
            if (auto token = user_token(); token) {
                const Impersonation as_user(token.get());
                DeleteFileW(node.mapped().partial.c_str());
            }
            spdlog::info("files: viewer {} cancelled sending \"{}\"", viewer, to_utf8(node.mapped().name));
        }
        downloads.erase(key);
    }

    void forget_viewer(std::uint64_t viewer) {
        std::erase_if(uploads, [viewer](const auto& entry) { return entry.first.first == viewer; });
        std::erase_if(downloads, [viewer](const auto& entry) { return entry.first.first == viewer; });
    }

    // Keeps every download's window full.
    void pump() {
        std::vector<std::byte> buffer(kChunkSize);
        for (auto it = downloads.begin(); it != downloads.end();) {
            auto& [key, download] = *it;
            bool  gone = false;
            while (download.sent < download.size && download.sent - download.acked < kWindowChunks * kChunkSize) {
                const auto want = static_cast<DWORD>(std::min<std::uint64_t>(kChunkSize, download.size - download.sent));
                DWORD      read = 0;
                if (ReadFile(download.file.get(), buffer.data(), want, &read, nullptr) == FALSE || read != want) {
                    fail(key.first, key.second, "the file changed while it was being sent");
                    gone = true;
                    break;
                }
                const ChannelMessage message{.op = file_op::data,
                                          .header = to_json(ReplyHeader{.id = key.second, .offset = download.sent}),
                                          .data = {buffer.begin(), buffer.begin() + read}};
                if (!hub.send_file(key.first, message)) {
                    gone = true;
                    break;
                }
                download.sent += read;
            }
            it = gone ? downloads.erase(it) : std::next(it);
        }
    }

    void expire() {
        const auto now = Clock::now();
        for (auto it = downloads.begin(); it != downloads.end();) {
            if (it->second.sent > it->second.acked && now - it->second.last_ack > kDownloadTimeout) {
                fail(it->first.first, it->first.second, "the download stalled; retry to resume it");
                it = downloads.erase(it);
            } else {
                ++it;
            }
        }
        std::erase_if(uploads, [now](const auto& entry) { return now - entry.second.last_activity > kUploadTimeout; });
    }
};

FileTransfers::FileTransfers(FilesConfig config, ViewerHub& hub)
    : impl_(std::make_unique<Impl>(std::move(config), hub)) {}

FileTransfers::~FileTransfers() = default;

void FileTransfers::handle(std::uint64_t viewer, ChannelMessage message) {
    impl_->push(Request{.viewer = viewer, .message = std::move(message)});
}

void FileTransfers::drop_viewer(std::uint64_t viewer) {
    impl_->push(Drop{.viewer = viewer});
}

}  // namespace hawk::service
