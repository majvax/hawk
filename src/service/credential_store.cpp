#include "credential_store.hpp"

#include <windows.h>
#include <dpapi.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>
#include <vector>

namespace hawk::service {

namespace {

const std::filesystem::path kDataDirectory = R"(C:\ProgramData\HawkService)";
const std::filesystem::path kCredentialPath = kDataDirectory / "credential.bin";
const std::filesystem::path kEnrollCodePath = kDataDirectory / "enroll-code.txt";

[[nodiscard]] std::optional<std::vector<char>> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::vector<char>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Removes the DATA_BLOB's LocalAlloc'd buffer when it goes out of scope.
struct LocalBlob {
    DATA_BLOB blob{};
    LocalBlob() = default;
    ~LocalBlob() {
        if (blob.pbData != nullptr) {
            SecureZeroMemory(blob.pbData, blob.cbData);
            LocalFree(blob.pbData);
        }
    }
    LocalBlob(const LocalBlob&) = delete;
    LocalBlob& operator=(const LocalBlob&) = delete;
    LocalBlob(LocalBlob&&) = delete;
    LocalBlob& operator=(LocalBlob&&) = delete;
};

}  // namespace

std::optional<std::string> load_credential() {
    auto encrypted = read_file(kCredentialPath);
    if (!encrypted.has_value() || encrypted->empty()) {
        return std::nullopt;
    }

    DATA_BLOB input{.cbData = static_cast<DWORD>(encrypted->size()),
                    .pbData = reinterpret_cast<BYTE*>(encrypted->data())};
    LocalBlob output;
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output.blob) ==
        FALSE) {
        spdlog::error("credential: can't decrypt {} (Win32 error {}); re-enroll this machine",
                      kCredentialPath.string(), GetLastError());
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(output.blob.pbData), output.blob.cbData);
}

bool save_credential(const std::string& credential) {
    std::string plain = credential;
    DATA_BLOB input{.cbData = static_cast<DWORD>(plain.size()), .pbData = reinterpret_cast<BYTE*>(plain.data())};
    LocalBlob output;
    const BOOL protected_ok = CryptProtectData(&input, L"hawk relay credential", nullptr, nullptr, nullptr,
                                               CRYPTPROTECT_UI_FORBIDDEN, &output.blob);
    SecureZeroMemory(plain.data(), plain.size());
    if (protected_ok == FALSE) {
        spdlog::error("credential: CryptProtectData failed: Win32 error {}", GetLastError());
        return false;
    }

    // Write to a temporary file and rename over the old one, so a crash
    // mid-write never leaves a truncated credential behind.
    std::error_code error;
    std::filesystem::create_directories(kDataDirectory, error);
    const auto temporary = std::filesystem::path(kCredentialPath).concat(".tmp");
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(output.blob.pbData), static_cast<std::streamsize>(output.blob.cbData));
        if (!file) {
            spdlog::error("credential: writing {} failed", temporary.string());
            return false;
        }
    }
    std::filesystem::rename(temporary, kCredentialPath, error);
    if (error) {
        spdlog::error("credential: saving {} failed: {}", kCredentialPath.string(), error.message());
        return false;
    }
    return true;
}

std::optional<std::string> load_enroll_code() {
    auto contents = read_file(kEnrollCodePath);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    std::string code(contents->begin(), contents->end());
    std::erase_if(code, [](unsigned char c) { return std::isspace(c) != 0; });
    if (code.empty()) {
        return std::nullopt;
    }
    return code;
}

void delete_enroll_code() {
    std::error_code error;
    std::filesystem::remove(kEnrollCodePath, error);
    if (error) {
        spdlog::warn("credential: couldn't delete {}: {}", kEnrollCodePath.string(), error.message());
    }
}

}  // namespace hawk::service
