#include "machine_key.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <format>
#include <utility>

namespace hawk::service {

namespace {

constexpr DWORD kP256CoordinateSize = 32;
constexpr DWORD kSha256Size = 32;

[[nodiscard]] std::string status_error(std::string_view context, SECURITY_STATUS status) {
    return std::format("{}: 0x{:08X}", context, static_cast<std::uint32_t>(status));
}

class ProviderHandle {
public:
    ProviderHandle() = default;
    ~ProviderHandle() {
        if (handle_ != 0) {
            NCryptFreeObject(handle_);
        }
    }
    ProviderHandle(const ProviderHandle&) = delete;
    ProviderHandle& operator=(const ProviderHandle&) = delete;
    ProviderHandle(ProviderHandle&&) = delete;
    ProviderHandle& operator=(ProviderHandle&&) = delete;

    [[nodiscard]] SECURITY_STATUS open(LPCWSTR provider) { return NCryptOpenStorageProvider(&handle_, provider, 0); }
    [[nodiscard]] NCRYPT_PROV_HANDLE get() const noexcept { return handle_; }

private:
    NCRYPT_PROV_HANDLE handle_ = 0;
};

// TPM first; the software provider only when there's no usable TPM.
struct ProviderChoice {
    LPCWSTR          name;
    std::string_view storage;
};
constexpr std::array kProviders{
    ProviderChoice{.name = MS_PLATFORM_CRYPTO_PROVIDER, .storage = "tpm"},
    ProviderChoice{.name = MS_KEY_STORAGE_PROVIDER, .storage = "software"},
};

}  // namespace

struct MachineKey::Impl {
    NCRYPT_KEY_HANDLE key = 0;
    std::string_view  storage;

    Impl() = default;
    ~Impl() {
        if (key != 0) {
            NCryptFreeObject(key);
        }
    }
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;
};

MachineKey::MachineKey(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
MachineKey::MachineKey(MachineKey&&) noexcept = default;
MachineKey& MachineKey::operator=(MachineKey&&) noexcept = default;
MachineKey::~MachineKey() = default;

std::expected<MachineKey, std::string> MachineKey::create(const std::wstring& name) {
    std::string failures;
    for (const auto& choice : kProviders) {
        ProviderHandle provider;
        if (const SECURITY_STATUS status = provider.open(choice.name); status != ERROR_SUCCESS) {
            failures += status_error(std::format(" {} provider", choice.storage), status);
            continue;
        }

        auto impl = std::make_unique<Impl>();
        impl->storage = choice.storage;
        SECURITY_STATUS status =
            NCryptCreatePersistedKey(provider.get(), &impl->key, BCRYPT_ECDSA_P256_ALGORITHM, name.c_str(), 0,
                                     NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);
        if (status == ERROR_SUCCESS) {
            // Never exportable, whichever provider holds it. (The TPM
            // provider can't export private keys at all; this pins the
            // software fallback to the same rule.)
            DWORD export_policy = 0;
            status = NCryptSetProperty(impl->key, NCRYPT_EXPORT_POLICY_PROPERTY,
                                       reinterpret_cast<PBYTE>(&export_policy), sizeof(export_policy),
                                       NCRYPT_PERSIST_FLAG);
        }
        if (status == ERROR_SUCCESS) {
            status = NCryptFinalizeKey(impl->key, NCRYPT_SILENT_FLAG);
        }
        if (status == ERROR_SUCCESS) {
            return MachineKey(std::move(impl));
        }
        failures += status_error(std::format(" {} key", choice.storage), status);
    }
    return std::unexpected("creating machine key failed:" + failures);
}

std::expected<MachineKey, std::string> MachineKey::open(const std::wstring& name) {
    for (const auto& choice : kProviders) {
        ProviderHandle provider;
        if (provider.open(choice.name) != ERROR_SUCCESS) {
            continue;
        }
        auto impl = std::make_unique<Impl>();
        impl->storage = choice.storage;
        if (NCryptOpenKey(provider.get(), &impl->key, name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) ==
            ERROR_SUCCESS) {
            return MachineKey(std::move(impl));
        }
        impl->key = 0;
    }
    return std::unexpected("machine key not found");
}

std::expected<void, std::string> MachineKey::destroy(const std::wstring& name) {
    for (const auto& choice : kProviders) {
        ProviderHandle provider;
        if (provider.open(choice.name) != ERROR_SUCCESS) {
            continue;
        }
        NCRYPT_KEY_HANDLE key = 0;
        SECURITY_STATUS   status =
            NCryptOpenKey(provider.get(), &key, name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (status == NTE_BAD_KEYSET) {
            continue;  // not in this provider
        }
        if (status != ERROR_SUCCESS) {
            return std::unexpected(status_error(std::format("opening {} key to delete it", choice.storage), status));
        }
        // NCryptDeleteKey frees the handle whether or not it succeeds. No
        // flags: the TPM provider rejects NCRYPT_SILENT_FLAG here
        // (NTE_BAD_FLAGS), though the software provider accepts it.
        status = NCryptDeleteKey(key, 0);
        if (status != ERROR_SUCCESS) {
            return std::unexpected(status_error(std::format("deleting {} key", choice.storage), status));
        }
    }
    return {};
}

std::string_view MachineKey::storage() const noexcept {
    return impl_->storage;
}

std::expected<std::vector<std::byte>, std::string> MachineKey::public_key() const {
    DWORD size = 0;
    SECURITY_STATUS status = NCryptExportKey(impl_->key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0);
    if (status != ERROR_SUCCESS) {
        return std::unexpected(status_error("NCryptExportKey(size)", status));
    }
    std::vector<std::byte> blob(size);
    status = NCryptExportKey(impl_->key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, reinterpret_cast<PBYTE>(blob.data()), size,
                             &size, 0);
    if (status != ERROR_SUCCESS) {
        return std::unexpected(status_error("NCryptExportKey", status));
    }

    // BCRYPT_ECCKEY_BLOB header, then X, then Y.
    BCRYPT_ECCKEY_BLOB header{};
    if (size < sizeof(header)) {
        return std::unexpected("public key blob too short");
    }
    std::memcpy(&header, blob.data(), sizeof(header));
    if (header.cbKey != kP256CoordinateSize || size < sizeof(header) + 2 * kP256CoordinateSize) {
        return std::unexpected("unexpected public key size");
    }
    std::vector<std::byte> point;
    point.reserve(1 + 2 * kP256CoordinateSize);
    point.push_back(std::byte{0x04});
    point.insert(point.end(), blob.begin() + sizeof(header), blob.begin() + sizeof(header) + 2 * kP256CoordinateSize);
    return point;
}

std::expected<std::vector<std::byte>, std::string> MachineKey::sign(std::span<const std::byte> message) const {
    std::array<UCHAR, kSha256Size> digest{};
    BCRYPT_ALG_HANDLE              sha256 = nullptr;
    NTSTATUS result = BCryptOpenAlgorithmProvider(&sha256, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(result)) {
        return std::unexpected(status_error("BCryptOpenAlgorithmProvider(SHA256)", result));
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    result = BCryptCreateHash(sha256, &hash, nullptr, 0, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(result)) {
        // BCryptHashData takes a non-const pointer but only reads it.
        result = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(message.data())),
                                static_cast<ULONG>(message.size()), 0);
    }
    if (BCRYPT_SUCCESS(result)) {
        result = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(sha256, 0);
    if (!BCRYPT_SUCCESS(result)) {
        return std::unexpected(status_error("SHA-256", result));
    }

    std::vector<std::byte> signature(2 * kP256CoordinateSize);
    DWORD                  size = 0;
    const SECURITY_STATUS  status =
        NCryptSignHash(impl_->key, nullptr, digest.data(), static_cast<DWORD>(digest.size()),
                       reinterpret_cast<PBYTE>(signature.data()), static_cast<DWORD>(signature.size()), &size,
                       NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) {
        return std::unexpected(status_error("NCryptSignHash", status));
    }
    signature.resize(size);
    return signature;
}

}  // namespace hawk::service
