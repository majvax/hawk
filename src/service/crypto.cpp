#include "crypto.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstring>
#include <utility>

#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif

namespace hawk::crypto {

namespace {

constexpr ULONG kCoordinateSize = 32;

// Algorithm providers are opened once and shared: CNG allows that across
// threads, and opening one costs far more than using it.
class Provider {
public:
    // `chaining_mode` is set on the handle once open (AES's GCM mode).
    explicit Provider(LPCWSTR algorithm, ULONG flags = 0, LPCWSTR chaining_mode = nullptr) {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&handle_, algorithm, nullptr, flags))) {
            handle_ = nullptr;
            return;
        }
        if (chaining_mode != nullptr) {
            auto* mode = const_cast<wchar_t*>(chaining_mode);
            const auto size = static_cast<ULONG>((wcslen(mode) + 1) * sizeof(wchar_t));
            if (!BCRYPT_SUCCESS(
                    BCryptSetProperty(handle_, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(mode), size, 0))) {
                BCryptCloseAlgorithmProvider(handle_, 0);
                handle_ = nullptr;
            }
        }
    }
    ~Provider() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }
    Provider(const Provider&) = delete;
    Provider& operator=(const Provider&) = delete;
    Provider(Provider&&) = delete;
    Provider& operator=(Provider&&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

const Provider& sha256_provider() {
    static const Provider provider(BCRYPT_SHA256_ALGORITHM);
    return provider;
}
const Provider& hmac_provider() {
    static const Provider provider(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    return provider;
}
const Provider& ecdsa_provider() {
    static const Provider provider(BCRYPT_ECDSA_P256_ALGORITHM);
    return provider;
}
const Provider& ecdh_provider() {
    static const Provider provider(BCRYPT_ECDH_P256_ALGORITHM);
    return provider;
}
const Provider& aes_gcm_provider() {
    static const Provider provider(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_GCM);
    return provider;
}

PUCHAR mutable_bytes(std::span<const std::byte> data) {
    // CNG takes non-const pointers for input it only reads.
    return reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data()));
}

// A CNG key handle, destroyed with its owner.
struct KeyHandle {
    BCRYPT_KEY_HANDLE handle = nullptr;
    KeyHandle() = default;
    explicit KeyHandle(BCRYPT_KEY_HANDLE key) : handle(key) {}
    ~KeyHandle() {
        if (handle != nullptr) {
            BCryptDestroyKey(handle);
        }
    }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    KeyHandle(KeyHandle&& other) noexcept : handle(std::exchange(other.handle, nullptr)) {}
    KeyHandle& operator=(KeyHandle&& other) noexcept {
        std::swap(handle, other.handle);
        return *this;
    }
};

// An uncompressed point as a BCRYPT_ECCKEY_BLOB with `magic`.
std::optional<KeyHandle> import_public_key(const Provider& provider, ULONG magic, std::span<const std::byte> key) {
    if (!is_public_key(key) || provider.get() == nullptr) {
        return std::nullopt;
    }
    std::vector<std::byte> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 2 * kCoordinateSize);
    const BCRYPT_ECCKEY_BLOB header{.dwMagic = magic, .cbKey = kCoordinateSize};
    std::memcpy(blob.data(), &header, sizeof(header));
    std::copy(key.begin() + 1, key.end(), blob.begin() + sizeof(header));
    BCRYPT_KEY_HANDLE handle = nullptr;
    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(provider.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, &handle,
                                            reinterpret_cast<PUCHAR>(blob.data()), static_cast<ULONG>(blob.size()),
                                            0))) {
        return std::nullopt;
    }
    return KeyHandle(handle);
}

}  // namespace

Bytes as_bytes(std::string_view text) {
    Bytes bytes(text.size());
    std::ranges::transform(text, bytes.begin(), [](char c) { return static_cast<std::byte>(c); });
    return bytes;
}

std::string base64_encode(std::span<const std::byte> data) {
    const auto* bytes = reinterpret_cast<const BYTE*>(data.data());
    const auto  flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD       length = 0;
    if (CryptBinaryToStringA(bytes, static_cast<DWORD>(data.size()), flags, nullptr, &length) == FALSE) {
        return {};
    }
    std::string text(length, '\0');
    if (CryptBinaryToStringA(bytes, static_cast<DWORD>(data.size()), flags, text.data(), &length) == FALSE) {
        return {};
    }
    text.resize(length);  // drop the terminator the size query counted
    return text;
}

std::optional<Bytes> base64_decode(std::string_view text) {
    DWORD length = 0;
    if (CryptStringToBinaryA(text.data(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, nullptr, &length,
                             nullptr, nullptr) == FALSE) {
        return std::nullopt;
    }
    Bytes data(length);
    if (CryptStringToBinaryA(text.data(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                             reinterpret_cast<BYTE*>(data.data()), &length, nullptr, nullptr) == FALSE) {
        return std::nullopt;
    }
    data.resize(length);
    return data;
}

void random(std::span<std::byte> out) {
    BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(out.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

namespace {

Sha256Digest finish_hash(BCRYPT_ALG_HANDLE algorithm, std::span<const std::byte> secret,
                         std::initializer_list<std::span<const std::byte>> parts) {
    Sha256Digest       digest{};
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (algorithm == nullptr ||
        !BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, mutable_bytes(secret),
                                         static_cast<ULONG>(secret.size()), 0))) {
        return digest;
    }
    for (const auto part : parts) {
        BCryptHashData(hash, mutable_bytes(part), static_cast<ULONG>(part.size()), 0);
    }
    BCryptFinishHash(hash, reinterpret_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    return digest;
}

}  // namespace

Sha256Digest sha256(std::span<const std::byte> data) {
    return finish_hash(sha256_provider().get(), {}, {data});
}

namespace {

[[nodiscard]] BCRYPT_HASH_HANDLE new_reusable_hash() {
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (sha256_provider().get() == nullptr ||
        !BCRYPT_SUCCESS(
            BCryptCreateHash(sha256_provider().get(), &hash, nullptr, 0, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG))) {
        return nullptr;
    }
    return hash;
}

}  // namespace

Sha256Stream::Sha256Stream() : hash_(new_reusable_hash()) {}

Sha256Stream::Sha256Stream(Sha256Stream&& other) noexcept : hash_(std::exchange(other.hash_, nullptr)) {}

Sha256Stream& Sha256Stream::operator=(Sha256Stream&& other) noexcept {
    if (this != &other) {
        if (hash_ != nullptr) {
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
        }
        hash_ = std::exchange(other.hash_, nullptr);
    }
    return *this;
}

Sha256Stream::~Sha256Stream() {
    if (hash_ != nullptr) {
        BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
    }
}

void Sha256Stream::update(std::span<const std::byte> data) {
    if (hash_ != nullptr) {
        BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hash_), mutable_bytes(data), static_cast<ULONG>(data.size()), 0);
    }
}

Sha256Digest Sha256Stream::finish() {
    Sha256Digest digest{};
    if (hash_ != nullptr) {
        BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hash_), reinterpret_cast<PUCHAR>(digest.data()),
                         static_cast<ULONG>(digest.size()), 0);
    }
    return digest;
}

Sha256Digest hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> data) {
    // CNG refuses an empty HMAC secret; HMAC pads a short key with zeros
    // anyway, so one zero byte is the same key.
    static constexpr std::array<std::byte, 1> kZero{};
    return finish_hash(hmac_provider().get(), key.empty() ? std::span<const std::byte>(kZero) : key, {data});
}

Bytes hkdf_sha256(std::span<const std::byte> ikm, std::span<const std::byte> salt, std::string_view info,
                  std::size_t length) {
    // Extract: an empty salt means a block of zeros.
    static constexpr std::array<std::byte, 32> kZeroSalt{};
    const auto prk = hmac_sha256(salt.empty() ? std::span<const std::byte>(kZeroSalt) : salt, ikm);
    // Expand.
    const auto  info_bytes = as_bytes(info);
    Bytes       okm;
    Sha256Digest block{};
    std::size_t  block_size = 0;
    for (std::uint8_t counter = 1; okm.size() < length; ++counter) {
        Bytes input(block.begin(), block.begin() + static_cast<std::ptrdiff_t>(block_size));
        input.insert(input.end(), info_bytes.begin(), info_bytes.end());
        input.push_back(static_cast<std::byte>(counter));
        block = hmac_sha256(prk, input);
        block_size = block.size();
        okm.insert(okm.end(), block.begin(), block.end());
    }
    okm.resize(length);
    return okm;
}

bool equal(std::span<const std::byte> lhs, std::span<const std::byte> rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    std::byte difference{0};
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        difference |= lhs[i] ^ rhs[i];
    }
    return difference == std::byte{0};
}

bool is_public_key(std::span<const std::byte> key) {
    return key.size() == public_key_size && key[0] == std::byte{0x04};
}

bool ecdsa_verify(std::span<const std::byte> public_key, std::span<const std::byte> message,
                  std::span<const std::byte> signature) {
    if (signature.size() != 2 * kCoordinateSize) {
        return false;
    }
    auto key = import_public_key(ecdsa_provider(), BCRYPT_ECDSA_PUBLIC_P256_MAGIC, public_key);
    if (!key.has_value()) {
        return false;
    }
    const auto digest = sha256(message);
    return BCRYPT_SUCCESS(BCryptVerifySignature(key->handle, nullptr, mutable_bytes(digest),
                                                static_cast<ULONG>(digest.size()), mutable_bytes(signature),
                                                static_cast<ULONG>(signature.size()), 0));
}

// --- AesGcm ---------------------------------------------------------------------

struct AesGcm::Impl {
    KeyHandle key;
};

AesGcm::AesGcm(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
AesGcm::AesGcm(AesGcm&&) noexcept = default;
AesGcm& AesGcm::operator=(AesGcm&&) noexcept = default;
AesGcm::~AesGcm() = default;

std::optional<AesGcm> AesGcm::create(std::span<const std::byte> key) {
    const auto& provider = aes_gcm_provider();
    if (key.size() != aes_key_size || provider.get() == nullptr) {
        return std::nullopt;
    }
    BCRYPT_KEY_HANDLE handle = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(provider.get(), &handle, nullptr, 0, mutable_bytes(key),
                                                   static_cast<ULONG>(key.size()), 0))) {
        return std::nullopt;
    }
    auto impl = std::make_unique<Impl>();
    impl->key = KeyHandle(handle);
    return AesGcm(std::move(impl));
}

Bytes AesGcm::encrypt(std::span<const std::byte> nonce, std::span<const std::byte> plaintext,
                      std::span<const std::byte> aad) const {
    Bytes                                 out(plaintext.size() + gcm_tag_size);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = mutable_bytes(nonce);
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = mutable_bytes(aad);
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = reinterpret_cast<PUCHAR>(out.data() + plaintext.size());
    info.cbTag = static_cast<ULONG>(gcm_tag_size);
    ULONG written = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(impl_->key.handle, mutable_bytes(plaintext), static_cast<ULONG>(plaintext.size()),
                                      &info, nullptr, 0, reinterpret_cast<PUCHAR>(out.data()),
                                      static_cast<ULONG>(plaintext.size()), &written, 0))) {
        return {};
    }
    return out;
}

std::optional<Bytes> AesGcm::decrypt(std::span<const std::byte> nonce, std::span<const std::byte> sealed,
                                     std::span<const std::byte> aad) const {
    if (sealed.size() < gcm_tag_size) {
        return std::nullopt;
    }
    const auto                            length = sealed.size() - gcm_tag_size;
    Bytes                                 out(length);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = mutable_bytes(nonce);
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = mutable_bytes(aad);
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = mutable_bytes(sealed.subspan(length));
    info.cbTag = static_cast<ULONG>(gcm_tag_size);
    ULONG written = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(impl_->key.handle, mutable_bytes(sealed.first(length)),
                                      static_cast<ULONG>(length), &info, nullptr, 0,
                                      reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(length), &written,
                                      0))) {
        return std::nullopt;
    }
    return out;
}

// --- ExchangeKey -------------------------------------------------------------

struct ExchangeKey::Impl {
    KeyHandle key;
    Bytes     public_key;
};

ExchangeKey::ExchangeKey(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
ExchangeKey::ExchangeKey(ExchangeKey&&) noexcept = default;
ExchangeKey& ExchangeKey::operator=(ExchangeKey&&) noexcept = default;
ExchangeKey::~ExchangeKey() = default;

std::optional<ExchangeKey> ExchangeKey::generate() {
    const auto& provider = ecdh_provider();
    if (provider.get() == nullptr) {
        return std::nullopt;
    }
    BCRYPT_KEY_HANDLE handle = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(provider.get(), &handle, 256, 0))) {
        return std::nullopt;
    }
    auto impl = std::make_unique<Impl>();
    impl->key = KeyHandle(handle);
    if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(handle, 0))) {
        return std::nullopt;
    }
    ULONG size = 0;
    if (!BCRYPT_SUCCESS(BCryptExportKey(handle, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &size, 0))) {
        return std::nullopt;
    }
    Bytes blob(size);
    if (!BCRYPT_SUCCESS(BCryptExportKey(handle, nullptr, BCRYPT_ECCPUBLIC_BLOB, reinterpret_cast<PUCHAR>(blob.data()),
                                        size, &size, 0)) ||
        size != sizeof(BCRYPT_ECCKEY_BLOB) + 2 * kCoordinateSize) {
        return std::nullopt;
    }
    impl->public_key.push_back(std::byte{0x04});
    impl->public_key.insert(impl->public_key.end(), blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end());
    return ExchangeKey(std::move(impl));
}

const Bytes& ExchangeKey::public_key() const noexcept {
    return impl_->public_key;
}

std::optional<Bytes> ExchangeKey::agree(std::span<const std::byte> peer) const {
    auto peer_key = import_public_key(ecdh_provider(), BCRYPT_ECDH_PUBLIC_P256_MAGIC, peer);
    if (!peer_key.has_value()) {
        return std::nullopt;
    }
    BCRYPT_SECRET_HANDLE secret = nullptr;
    if (!BCRYPT_SUCCESS(BCryptSecretAgreement(impl_->key.handle, peer_key->handle, &secret, 0))) {
        return std::nullopt;
    }
    Bytes shared(kCoordinateSize);
    ULONG size = 0;
    const NTSTATUS status = BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr,
                                            reinterpret_cast<PUCHAR>(shared.data()), kCoordinateSize, &size, 0);
    BCryptDestroySecret(secret);
    if (!BCRYPT_SUCCESS(status) || size != kCoordinateSize) {
        return std::nullopt;
    }
    // CNG hands the raw secret back little-endian; WebCrypto, big-endian.
    std::ranges::reverse(shared);
    return shared;
}

}  // namespace hawk::crypto
