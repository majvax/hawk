#include "sas.hpp"

#include <windows.h>

#include <format>
#include <string>

namespace hawk::service {

namespace {

// "Disable or enable software Secure Attention Sequence": SendSAS from a
// service does nothing unless this is 1 (services) or 3 (services and ease
// of access apps). hawk-setup turns services on when it installs the
// machine (allow_software_sas in src/installer/src/machine.rs).
constexpr const wchar_t* kPolicyKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
constexpr const wchar_t* kPolicyValue = L"SoftwareSASGeneration";
constexpr DWORD          kServices = 1;
constexpr DWORD          kServicesAndEaseOfAccess = 3;

// The policy's value, or why there isn't one to go by: not set (which
// Windows reads as 0, none), set but not a DWORD, or not readable.
[[nodiscard]] std::expected<DWORD, std::string> software_sas_policy() {
    DWORD      value = 0;
    DWORD      size = sizeof(value);
    const LONG result =
        RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKey, kPolicyValue, RRF_RT_REG_DWORD, nullptr, &value, &size);
    switch (result) {
        case ERROR_SUCCESS:
            return value;
        case ERROR_FILE_NOT_FOUND:
            return std::unexpected(std::string("not set"));
        case ERROR_UNSUPPORTED_TYPE:
        case ERROR_MORE_DATA:
            return std::unexpected(std::string("set, but not a DWORD"));
        default:
            return std::unexpected(std::format("unreadable, error {}", result));
    }
}

using SendSasFn = VOID(WINAPI*)(BOOL);

// SendSAS lives in sas.dll, which mingw-w64 has a header for but no import
// library: loaded once, from System32 only.
[[nodiscard]] SendSasFn send_sas_function() {
    static const auto function = [] {
        const HMODULE module = LoadLibraryExW(L"sas.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        return module == nullptr
                   ? SendSasFn{nullptr}
                   : reinterpret_cast<SendSasFn>(reinterpret_cast<void*>(GetProcAddress(module, "SendSAS")));
    }();
    return function;
}

}  // namespace

std::expected<void, std::string> send_sas() {
    const auto policy = software_sas_policy();
    if (!policy.has_value() || (*policy != kServices && *policy != kServicesAndEaseOfAccess)) {
        return std::unexpected(std::format(
            "Windows on this machine doesn't let services press Ctrl+Alt+Del (SoftwareSASGeneration is {}). "
            "Run hawk-setup install machine on it again, or set the policy \"Disable or enable software Secure "
            "Attention Sequence\" to Services.",
            policy.has_value() ? std::to_string(*policy) : policy.error()));
    }
    const auto send = send_sas_function();
    if (send == nullptr) {
        return std::unexpected(std::string("SendSAS isn't available on this machine (sas.dll)"));
    }
    // FALSE: the caller is a service, not the signed-in user. It returns
    // nothing; with the policy on, Windows takes it.
    send(FALSE);
    return {};
}

}  // namespace hawk::service
