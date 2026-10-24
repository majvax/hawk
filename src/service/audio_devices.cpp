#include "audio_devices.hpp"

#include "win_util.hpp"

#include <windows.h>
#include <mmdeviceapi.h>
#include <objbase.h>
#include <propidl.h>
#include <propsys.h>
#include <wrl/client.h>

#include <algorithm>
#include <format>

using Microsoft::WRL::ComPtr;

namespace hawk::service {

namespace {

// PKEY_Device_FriendlyName, spelled out rather than pulled in through
// initguid.h for one constant.
constexpr PROPERTYKEY kFriendlyName{
    {0xa45c254e, 0xdf1c, 0x4efd, {0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0}}, 14};

class ComScope {
public:
    ComScope() : hresult_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComScope() {
        if (SUCCEEDED(hresult_)) {
            CoUninitialize();
        }
    }
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;
    ComScope(ComScope&&) = delete;
    ComScope& operator=(ComScope&&) = delete;

    // Already set up on this thread another way still lets COM be used.
    [[nodiscard]] bool ok() const noexcept { return SUCCEEDED(hresult_) || hresult_ == RPC_E_CHANGED_MODE; }

private:
    HRESULT hresult_;
};

[[nodiscard]] std::string device_id(IMMDevice& device) {
    LPWSTR id = nullptr;
    if (FAILED(device.GetId(&id)) || id == nullptr) {
        return {};
    }
    std::string text = win::to_utf8(id);
    CoTaskMemFree(id);
    return text;
}

[[nodiscard]] std::string friendly_name(IMMDevice& device) {
    ComPtr<IPropertyStore> store;
    if (FAILED(device.OpenPropertyStore(STGM_READ, &store))) {
        return {};
    }
    PROPVARIANT value;
    PropVariantInit(&value);
    std::string name;
    if (SUCCEEDED(store->GetValue(kFriendlyName, &value)) && value.vt == VT_LPWSTR && value.pwszVal != nullptr) {
        name = win::to_utf8(value.pwszVal);
    }
    PropVariantClear(&value);
    return name;
}

}  // namespace

std::expected<std::vector<AudioDevice>, std::string> list_audio_devices() {
    const ComScope com;
    if (!com.ok()) {
        return std::unexpected("CoInitializeEx failed");
    }
    ComPtr<IMMDeviceEnumerator> enumerator;
    if (const auto hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, IID_PPV_ARGS(&enumerator));
        FAILED(hr)) {
        return std::unexpected(std::format("no device enumerator (HRESULT {:#x})", static_cast<std::uint32_t>(hr)));
    }
    std::string default_id;
    if (ComPtr<IMMDevice> device; SUCCEEDED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device))) {
        default_id = device_id(*device.Get());
    }
    ComPtr<IMMDeviceCollection> collection;
    if (const auto hr = enumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &collection); FAILED(hr)) {
        return std::unexpected(std::format("couldn't list the devices (HRESULT {:#x})", static_cast<std::uint32_t>(hr)));
    }
    UINT count = 0;
    collection->GetCount(&count);
    std::vector<AudioDevice> devices;
    for (UINT index = 0; index < count; ++index) {
        ComPtr<IMMDevice> device;
        if (FAILED(collection->Item(index, &device))) {
            continue;
        }
        AudioDevice entry{.id = device_id(*device.Get()), .name = friendly_name(*device.Get())};
        if (entry.id.empty()) {
            continue;
        }
        entry.is_default = entry.id == default_id;
        if (entry.name.empty()) {
            entry.name = "Output device";
        }
        devices.push_back(std::move(entry));
    }
    return devices;
}

bool plausible_device_id(std::string_view id) noexcept {
    // "{0.0.0.00000000}.{8c6d2a5e-...}"
    return !id.empty() && id.size() <= 256 && std::ranges::all_of(id, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '{' || c == '}' ||
               c == '.' || c == '-' || c == '#' || c == '_';
    });
}

}  // namespace hawk::service
