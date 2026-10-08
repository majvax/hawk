#include "machine_identity.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <system_error>

namespace hawk::service {

namespace {

const std::filesystem::path kDataDirectory = R"(C:\ProgramData\HawkService)";
const std::filesystem::path kIdentityPath = kDataDirectory / "machine.txt";
const std::filesystem::path kEnrollCodePath = kDataDirectory / "enroll-code.txt";
const std::filesystem::path kLegacyCredentialPath = kDataDirectory / "credential.bin";
const std::filesystem::path kRelayPinsPath = kDataDirectory / "relay-pins.txt";

[[nodiscard]] std::optional<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

void remove_file(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
    if (error) {
        spdlog::warn("identity: couldn't delete {}: {}", path.string(), error.message());
    }
}

// Strips leading and trailing whitespace (key names contain spaces).
[[nodiscard]] std::string trim(const std::string& text) {
    constexpr std::string_view kWhitespace = " \t\r\n";
    const auto first = text.find_first_not_of(kWhitespace);
    if (first == std::string::npos) {
        return {};
    }
    const auto last = text.find_last_not_of(kWhitespace);
    return text.substr(first, last - first + 1);
}

[[nodiscard]] std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), length);
    return wide;
}

[[nodiscard]] std::string narrow(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int length =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), length, nullptr,
                        nullptr);
    return utf8;
}

}  // namespace

std::optional<MachineIdentity> load_machine_identity() {
    const auto contents = read_file(kIdentityPath);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    // Line 1: machine id. Line 2: key name.
    const auto newline = contents->find('\n');
    if (newline == std::string::npos) {
        return std::nullopt;
    }
    MachineIdentity identity{
        .machine_id = trim(contents->substr(0, newline)),
        .key_name = widen(trim(contents->substr(newline + 1))),
    };
    if (identity.machine_id.empty() || identity.key_name.empty()) {
        return std::nullopt;
    }
    return identity;
}

bool save_machine_identity(const MachineIdentity& identity) {
    // Write to a temporary file and rename over the old one, so a crash
    // mid-write never leaves a half-written identity behind.
    std::error_code error;
    std::filesystem::create_directories(kDataDirectory, error);
    const auto temporary = std::filesystem::path(kIdentityPath).concat(".tmp");
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file << identity.machine_id << '\n' << narrow(identity.key_name) << '\n';
        if (!file) {
            spdlog::error("identity: writing {} failed", temporary.string());
            return false;
        }
    }
    std::filesystem::rename(temporary, kIdentityPath, error);
    if (error) {
        spdlog::error("identity: saving {} failed: {}", kIdentityPath.string(), error.message());
        return false;
    }
    return true;
}

std::wstring new_machine_key_name() {
    std::array<UCHAR, 8> random{};
    BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::wstring name = L"HawkService Machine Key ";
    for (const UCHAR byte : random) {
        name += std::format(L"{:02x}", byte);
    }
    return name;
}

std::optional<std::string> load_enroll_code() {
    auto contents = read_file(kEnrollCodePath);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    auto code = trim(*contents);
    if (code.empty()) {
        return std::nullopt;
    }
    return code;
}

void delete_enroll_code() {
    remove_file(kEnrollCodePath);
}

void delete_legacy_credential() {
    if (std::filesystem::exists(kLegacyCredentialPath)) {
        remove_file(kLegacyCredentialPath);
        spdlog::info("identity: removed the old credential file; this machine now authenticates with its key");
    }
}

std::vector<std::string> load_relay_pins() {
    std::vector<std::string> pins;
    const auto contents = read_file(kRelayPinsPath);
    if (!contents.has_value()) {
        return pins;
    }
    std::size_t start = 0;
    while (start <= contents->size()) {
        const auto end = std::min(contents->find('\n', start), contents->size());
        if (auto pin = trim(contents->substr(start, end - start)); !pin.empty()) {
            pins.push_back(std::move(pin));
        }
        start = end + 1;
    }
    return pins;
}

}  // namespace hawk::service
