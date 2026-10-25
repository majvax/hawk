#include "metrics.hpp"

#include "win_util.hpp"

// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>  // ws2ipdef.h, which netioapi.h needs for GetIfTable2
#include <windows.h>
#include <winternl.h>
#include <dxgi.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#include <sddl.h>
#include <wrl/client.h>
// clang-format on

#include <glaze/glaze.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace hawk::service {

namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::system_clock;

const fs::path kMetricsDirectory = R"(C:\ProgramData\HawkService\metrics)";
const fs::path kMinutesPath = kMetricsDirectory / "minutes.bin";

constexpr std::size_t kSecondsKept = 3600;
constexpr std::int64_t kSecondsPerDay = 86400;
// FILETIME and kernel times count 100 ns.
constexpr double kTicksPerSecond = 1e7;
constexpr std::int64_t kFiletimeUnixEpoch = 116444736000000000LL;

// --- What's sent -----------------------------------------------------------------

struct CpuInfo {
    std::string   name;
    std::uint32_t cores = 0;    // physical
    std::uint32_t threads = 0;  // logical
};

struct GpuInfo {
    std::string   name;
    std::uint64_t dedicated = 0;  // bytes of VRAM
};

struct MachineInfo {
    std::string              hostname;
    std::string              os;
    CpuInfo                  cpu;
    std::uint64_t            memory = 0;
    std::vector<GpuInfo>     gpus;
    std::uint32_t            history_days = 0;
    std::vector<std::string> ranges;
};

struct GpuSample {
    std::string   name;
    double        util = 0;  // %, the busiest engine type, as Task Manager shows it
    std::uint64_t dedicated_used = 0;
    std::uint64_t dedicated_total = 0;
    std::uint64_t shared_used = 0;
    // °C, where the GPU reports it (GpuThermals); left out otherwise, which
    // an older dashboard ignores either way.
    std::optional<double> temp;
};

struct AdapterSample {
    std::string name;
    double      rx = 0;  // bytes a second
    double      tx = 0;
};

struct VolumeSample {
    std::string   name;  // "C:"
    std::string   label;
    std::uint64_t total = 0;
    std::uint64_t free = 0;
};

struct Sample {
    std::int64_t               t = 0;  // unix milliseconds
    double                     cpu = 0;
    std::vector<double>        cores;
    std::uint64_t              mem_total = 0;
    std::uint64_t              mem_used = 0;
    std::uint64_t              commit_used = 0;
    std::uint64_t              commit_limit = 0;
    std::vector<GpuSample>     gpus;
    double                     net_rx = 0;
    double                     net_tx = 0;
    std::vector<AdapterSample> adapters;
    double                     disk_read = 0;
    double                     disk_write = 0;
    std::vector<VolumeSample>  volumes;
    std::uint64_t              uptime = 0;  // seconds
    std::uint32_t              processes = 0;
    // °C, the hottest ACPI thermal zone (Counters::thermal_zone), where the
    // machine has one; left out otherwise.
    std::optional<double>      cpu_temp;
};

struct History {
    std::string               range;
    std::int64_t              step = 0;  // seconds per point
    std::vector<std::int64_t> t;         // unix seconds, the start of each point
    std::vector<double>       cpu;
    std::vector<double>       mem;
    std::vector<double>       gpu;
    std::vector<double>       vram;
    std::vector<double>       rx;
    std::vector<double>       tx;
    std::vector<double>       read;
    std::vector<double>       write;
};

struct ProcessRow {
    std::uint32_t pid = 0;
    std::uint32_t parent = 0;
    std::string   name;
    std::string   user;
    double        cpu = 0;  // % of the whole machine
    std::uint64_t memory = 0;   // working set
    std::uint64_t private_bytes = 0;
    std::uint32_t threads = 0;
    std::uint32_t handles = 0;
    std::uint32_t session = 0;
    std::int64_t  started = 0;  // unix milliseconds
};

struct ProcessList {
    std::int64_t            t = 0;
    std::vector<ProcessRow> processes;
};

struct ErrorHeader {
    std::string message;
};

struct RangeHeader {
    std::string range;
};

// --- History -----------------------------------------------------------------------

// The numbers a history point keeps: what the charts draw over time.
enum Column : std::uint8_t { kCpu, kMem, kGpu, kVram, kRx, kTx, kRead, kWrite, kColumns };

struct Point {
    std::int64_t                 time = 0;  // unix seconds
    std::array<double, kColumns> values{};
};

// On disk: little-endian time, then the columns, as they are in memory.
constexpr std::size_t kRecordSize = sizeof(std::int64_t) + sizeof(double) * kColumns;

[[nodiscard]] std::array<std::byte, kRecordSize> encode(const Point& point) {
    std::array<std::byte, kRecordSize> record{};
    std::memcpy(record.data(), &point.time, sizeof(point.time));
    std::memcpy(record.data() + sizeof(point.time), point.values.data(), sizeof(double) * kColumns);
    return record;
}

[[nodiscard]] Point decode(const char* record) {
    Point point;
    std::memcpy(&point.time, record, sizeof(point.time));
    std::memcpy(point.values.data(), record + sizeof(point.time), sizeof(double) * kColumns);
    return point;
}

// A range as the dashboard names it: how far back, and how coarse.
struct RangeSpec {
    std::string_view name;
    std::int64_t     span = 0;     // seconds
    std::int64_t     step = 0;     // seconds per point
    bool             seconds = false;  // from the one-a-second history
};

constexpr std::array kRanges{
    RangeSpec{.name = "5m", .span = 300, .step = 1, .seconds = true},
    RangeSpec{.name = "1h", .span = 3600, .step = 5, .seconds = true},
    RangeSpec{.name = "24h", .span = kSecondsPerDay, .step = 120, .seconds = false},
    RangeSpec{.name = "7d", .span = 7 * kSecondsPerDay, .step = 900, .seconds = false},
    RangeSpec{.name = "30d", .span = 30 * kSecondsPerDay, .step = 3600, .seconds = false},
    RangeSpec{.name = "90d", .span = 90 * kSecondsPerDay, .step = 3 * 3600, .seconds = false},
};

// `points` averaged into `step`-second buckets from `since` on; buckets
// with nothing in them are left out, which the charts draw as a gap.
[[nodiscard]] History downsample(const RangeSpec& range, const std::deque<Point>& points, std::int64_t since) {
    History history;
    history.range = std::string(range.name);
    history.step = range.step;
    std::int64_t                 bucket = -1;
    std::array<double, kColumns> sums{};
    int                          count = 0;
    const auto flush = [&] {
        if (count == 0) {
            return;
        }
        history.t.push_back(bucket);
        std::array<std::vector<double>*, kColumns> columns{&history.cpu, &history.mem,  &history.gpu, &history.vram,
                                                            &history.rx,  &history.tx,   &history.read, &history.write};
        for (std::size_t i = 0; i < kColumns; ++i) {
            const double mean = sums.at(i) / count;
            // Percentages to a tenth; bytes to whole numbers.
            columns.at(i)->push_back(i == kCpu || i == kGpu ? std::round(mean * 10) / 10 : std::round(mean));
        }
        sums = {};
        count = 0;
    };
    for (const auto& point : points) {
        if (point.time < since) {
            continue;
        }
        const auto start = point.time - point.time % range.step;
        if (start != bucket) {
            flush();
            bucket = start;
        }
        for (std::size_t i = 0; i < kColumns; ++i) {
            sums.at(i) += point.values.at(i);
        }
        ++count;
    }
    flush();
    return history;
}

// --- Reading the machine -------------------------------------------------------------

[[nodiscard]] std::int64_t unix_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}

[[nodiscard]] std::uint64_t ticks(const LARGE_INTEGER& value) {
    return static_cast<std::uint64_t>(value.QuadPart);
}

[[nodiscard]] std::string registry_string(HKEY root, const wchar_t* path, const wchar_t* name) {
    std::array<wchar_t, 512> buffer{};
    DWORD                    size = sizeof(buffer);
    if (RegGetValueW(root, path, name, RRF_RT_REG_SZ, nullptr, buffer.data(), &size) != ERROR_SUCCESS) {
        return {};
    }
    return win::to_utf8(buffer.data());
}

[[nodiscard]] std::uint32_t physical_cores() {
    DWORD length = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length);
    std::vector<std::byte> buffer(length);
    auto* info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (length == 0 || GetLogicalProcessorInformationEx(RelationProcessorCore, info, &length) == FALSE) {
        return 0;
    }
    std::uint32_t cores = 0;
    for (DWORD offset = 0; offset < length;) {
        const auto* entry = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() + offset);
        cores += entry->Relationship == RelationProcessorCore ? 1 : 0;
        offset += entry->Size;
    }
    return cores;
}

// A GPU as DXGI knows it; LUIDs are how the performance counters name it.
struct Gpu {
    std::uint64_t luid = 0;
    std::string   name;
    std::uint64_t dedicated = 0;
    std::uint32_t vendor = 0;  // PCI ids, to find it in NVML
    std::uint32_t device = 0;
};

[[nodiscard]] std::uint64_t luid_value(LONG high, DWORD low) {
    return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(high)) << 32U) | low;
}

[[nodiscard]] std::vector<Gpu> list_gpus() {
    std::vector<Gpu>     gpus;
    ComPtr<IDXGIFactory1> factory;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), &factory))) {
        return gpus;
    }
    ComPtr<IDXGIAdapter1> adapter;
    for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 desc{};
        if (SUCCEEDED(adapter->GetDesc1(&desc)) && (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0) {
            gpus.push_back(Gpu{.luid = luid_value(desc.AdapterLuid.HighPart, desc.AdapterLuid.LowPart),
                               .name = win::to_utf8(desc.Description),
                               .dedicated = desc.DedicatedVideoMemory,
                               .vendor = desc.VendorId,
                               .device = desc.DeviceId});
        }
        adapter.Reset();
    }
    return gpus;
}

// "...luid_0x00000000_0x0000C4A8_..." in a counter instance name, as a value.
[[nodiscard]] std::optional<std::uint64_t> instance_luid(std::wstring_view instance) {
    const auto at = instance.find(L"luid_0x");
    if (at == std::wstring_view::npos || instance.size() < at + 26) {
        return std::nullopt;
    }
    const auto hex = [&](std::size_t from) -> std::optional<std::uint32_t> {
        std::uint32_t value = 0;
        for (std::size_t i = from; i < from + 8; ++i) {
            const wchar_t c = instance[i];
            value <<= 4U;
            if (c >= L'0' && c <= L'9') {
                value |= static_cast<std::uint32_t>(c - L'0');
            } else if (c >= L'a' && c <= L'f') {
                value |= static_cast<std::uint32_t>(c - L'a' + 10);
            } else if (c >= L'A' && c <= L'F') {
                value |= static_cast<std::uint32_t>(c - L'A' + 10);
            } else {
                return std::nullopt;
            }
        }
        return value;
    };
    const auto high = hex(at + 7);
    const auto low = hex(at + 18);
    if (!high.has_value() || !low.has_value()) {
        return std::nullopt;
    }
    return (static_cast<std::uint64_t>(*high) << 32U) | *low;
}

// Every instance of a wildcard counter, by name.
[[nodiscard]] std::vector<std::pair<std::wstring, double>> counter_array(PDH_HCOUNTER counter) {
    std::vector<std::pair<std::wstring, double>> values;
    if (counter == nullptr) {
        return values;
    }
    DWORD size = 0;
    DWORD count = 0;
    if (PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, nullptr) !=
        static_cast<PDH_STATUS>(PDH_MORE_DATA)) {
        return values;
    }
    std::vector<std::byte> buffer(size);
    auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buffer.data());
    if (PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, items) != ERROR_SUCCESS) {
        return values;
    }
    for (DWORD i = 0; i < count; ++i) {
        if (items[i].FmtValue.CStatus == PDH_CSTATUS_VALID_DATA || items[i].FmtValue.CStatus == PDH_CSTATUS_NEW_DATA) {
            values.emplace_back(items[i].szName, items[i].FmtValue.doubleValue);
        }
    }
    return values;
}

[[nodiscard]] double counter_value(PDH_HCOUNTER counter) {
    PDH_FMT_COUNTERVALUE value{};
    if (counter == nullptr || PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &value) != ERROR_SUCCESS ||
        (value.CStatus != PDH_CSTATUS_VALID_DATA && value.CStatus != PDH_CSTATUS_NEW_DATA)) {
        return 0;
    }
    return value.doubleValue;
}

// A reading worth showing, in °C: sensors that aren't there read 0 K, 0 or
// something absurd rather than failing.
[[nodiscard]] bool plausible_temperature(double celsius) {
    return celsius > 1 && celsius < 150;
}

// Disk throughput, the GPU counters and the thermal zones, through PDH by
// their English names, so a German or French Windows reads the same ones.
class Counters {
public:
    Counters() {
        if (PdhOpenQueryW(nullptr, 0, &query_) != ERROR_SUCCESS) {
            query_ = nullptr;
            spdlog::warn("metrics: performance counters unavailable; no disk throughput or GPU numbers");
            return;
        }
        disk_read_ = add(L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec");
        disk_write_ = add(L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec");
        gpu_engine_ = add(L"\\GPU Engine(*)\\Utilization Percentage");
        gpu_dedicated_ = add(L"\\GPU Adapter Memory(*)\\Dedicated Usage");
        gpu_shared_ = add(L"\\GPU Adapter Memory(*)\\Shared Usage");
        // Kelvin: tenths of one where Windows has the precise counter.
        thermal_precise_ = add(L"\\Thermal Zone Information(*)\\High Precision Temperature");
        thermal_ = add(L"\\Thermal Zone Information(*)\\Temperature");
        PdhCollectQueryData(query_);
    }
    ~Counters() {
        if (query_ != nullptr) {
            PdhCloseQuery(query_);
        }
    }
    Counters(const Counters&) = delete;
    Counters& operator=(const Counters&) = delete;
    Counters(Counters&&) = delete;
    Counters& operator=(Counters&&) = delete;

    void collect() {
        if (query_ != nullptr) {
            PdhCollectQueryData(query_);
        }
    }

    [[nodiscard]] double disk_read() const { return counter_value(disk_read_); }
    [[nodiscard]] double disk_write() const { return counter_value(disk_write_); }

    // Per GPU: like Task Manager, the busiest engine type (3D, Copy,
    // VideoDecode...), each type's engines summed across processes.
    [[nodiscard]] std::map<std::uint64_t, double> gpu_utilisation() const {
        std::map<std::uint64_t, std::map<std::wstring, double>> by_type;
        for (const auto& [name, value] : counter_array(gpu_engine_)) {
            const auto luid = instance_luid(name);
            const auto type = name.find(L"engtype_");
            if (!luid.has_value() || type == std::wstring::npos) {
                continue;
            }
            by_type[*luid][name.substr(type + 8)] += value;
        }
        std::map<std::uint64_t, double> result;
        for (const auto& [luid, types] : by_type) {
            double busiest = 0;
            for (const auto& [type, value] : types) {
                busiest = std::max(busiest, value);
            }
            result[luid] = std::min(busiest, 100.0);
        }
        return result;
    }

    [[nodiscard]] std::map<std::uint64_t, double> gpu_dedicated() const { return per_luid(gpu_dedicated_); }
    [[nodiscard]] std::map<std::uint64_t, double> gpu_shared() const { return per_luid(gpu_shared_); }

    // The hottest ACPI thermal zone, in °C: what Windows reads for its own
    // thermal policy, through PDH so it never waits on WMI. Often the
    // board's or the chipset's rather than the CPU package's, sometimes a
    // fixed number, and absent from many desktops: nullopt then. A fixed
    // number is the common fake (290 K, 16.85 °C): readings under 20 °C are
    // dropped, and so is a zone that hasn't moved at all in ten minutes.
    [[nodiscard]] std::optional<double> thermal_zone() {
        auto readings = counter_array(thermal_precise_);
        for (auto& [name, value] : readings) {
            value /= 10;
        }
        if (readings.empty()) {
            readings = counter_array(thermal_);
        }
        const auto            now = std::chrono::steady_clock::now();
        std::optional<double> hottest;
        for (const auto& [name, kelvin] : readings) {
            auto& zone = zones_[name];
            if (zone.changed == std::chrono::steady_clock::time_point{} || kelvin != zone.kelvin) {
                zone = Zone{.kelvin = kelvin, .changed = now};
            }
            const double celsius = kelvin - 273.15;
            if (now - zone.changed >= kStuckZone || celsius < kColdestZone || !plausible_temperature(celsius)) {
                continue;
            }
            hottest = std::max(hottest.value_or(celsius), celsius);
        }
        return hottest;
    }

private:
    [[nodiscard]] PDH_HCOUNTER add(const wchar_t* path) const {
        PDH_HCOUNTER counter = nullptr;
        if (PdhAddEnglishCounterW(query_, path, 0, &counter) != ERROR_SUCCESS) {
            spdlog::info("metrics: no counter {}", win::to_utf8(path));
            return nullptr;
        }
        return counter;
    }

    [[nodiscard]] static std::map<std::uint64_t, double> per_luid(PDH_HCOUNTER counter) {
        std::map<std::uint64_t, double> result;
        for (const auto& [name, value] : counter_array(counter)) {
            if (const auto luid = instance_luid(name); luid.has_value()) {
                result[*luid] += value;
            }
        }
        return result;
    }

    PDH_HQUERY   query_ = nullptr;
    PDH_HCOUNTER disk_read_ = nullptr;
    PDH_HCOUNTER disk_write_ = nullptr;
    PDH_HCOUNTER gpu_engine_ = nullptr;
    PDH_HCOUNTER gpu_dedicated_ = nullptr;
    PDH_HCOUNTER gpu_shared_ = nullptr;
    PDH_HCOUNTER thermal_precise_ = nullptr;
    PDH_HCOUNTER thermal_ = nullptr;

    // A thermal zone's last reading, and when it last moved.
    struct Zone {
        double                                kelvin = 0;
        std::chrono::steady_clock::time_point changed{};
    };
    static constexpr std::chrono::minutes kStuckZone{10};
    static constexpr double               kColdestZone = 20;
    std::map<std::wstring, Zone>          zones_;
};

// The graphics kernel's thunks and the bits of their structures used here,
// declared rather than taken from d3dkmthk.h, which MinGW's headers don't
// all have the WDDM 2.4 parts of. Layouts as in the Windows SDK.
namespace kmt {

using Handle = UINT;

struct OpenAdapterFromLuid {
    LUID   luid;
    Handle adapter;
};

struct CloseAdapter {
    Handle adapter;
};

struct QueryAdapterInfo {
    Handle adapter;
    UINT   type;  // KMTQUERYADAPTERINFOTYPE
    void*  data;
    UINT   size;
};

// D3DKMT_ADAPTER_PERFDATA, what Task Manager's GPU temperature comes from.
struct AdapterPerfData {
    UINT32    physical_adapter_index;
    ULONGLONG memory_frequency;
    ULONGLONG max_memory_frequency;
    ULONGLONG max_memory_frequency_oc;
    ULONGLONG memory_bandwidth;
    ULONGLONG pcie_bandwidth;
    ULONG     fan_rpm;
    ULONG     power;        // tenths of a percent
    ULONG     temperature;  // tenths of a degree Celsius; 0 when unknown
    UCHAR     power_state_override;
};

// KMTQAITYPE_ADAPTERPERFDATA, WDDM 2.4 (Windows 10 1803) and later.
constexpr UINT kAdapterPerfData = 62;

using OpenAdapterFromLuidFn = NTSTATUS(APIENTRY*)(OpenAdapterFromLuid*);
using CloseAdapterFn = NTSTATUS(APIENTRY*)(const CloseAdapter*);
using QueryAdapterInfoFn = NTSTATUS(APIENTRY*)(const QueryAdapterInfo*);

}  // namespace kmt

// NVML, the NVIDIA driver's management library, likewise declared here.
namespace nvml {

using Device = void*;

struct PciInfo {
    char         bus_id_legacy[16];
    unsigned int domain;
    unsigned int bus;
    unsigned int device;
    unsigned int pci_device_id;  // device id << 16 | vendor id
    unsigned int pci_subsystem_id;
    char         bus_id[32];
};

constexpr int kSuccess = 0;
constexpr int kTemperatureGpu = 0;

using InitFn = int(__cdecl*)();
using ShutdownFn = int(__cdecl*)();
using CountFn = int(__cdecl*)(unsigned int*);
using HandleFn = int(__cdecl*)(unsigned int, Device*);
using PciInfoFn = int(__cdecl*)(Device, PciInfo*);
using TemperatureFn = int(__cdecl*)(Device, int, unsigned int*);

}  // namespace nvml

template <typename Function>
[[nodiscard]] Function load(HMODULE module, const char* name) {
    return module == nullptr ? nullptr : reinterpret_cast<Function>(reinterpret_cast<void*>(GetProcAddress(module, name)));
}

// GPU temperatures, as Task Manager reads them: each adapter's performance
// data from the graphics kernel (WDDM 2.4 and later), whatever the vendor.
// For an NVIDIA card that doesn't report one there, NVML from System32,
// where the driver installs it. Both are loaded at run time and asked
// nothing that waits; with neither, a GPU simply has no temperature.
class GpuThermals {
public:
    explicit GpuThermals(const std::vector<Gpu>& gpus) : gpus_(gpus) {
        for (const auto& gpu : gpus) {
            luids_.insert(gpu.luid);
        }
        HMODULE gdi = GetModuleHandleW(L"gdi32.dll");
        if (gdi == nullptr) {
            gdi = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
        open_ = load<kmt::OpenAdapterFromLuidFn>(gdi, "D3DKMTOpenAdapterFromLuid");
        close_ = load<kmt::CloseAdapterFn>(gdi, "D3DKMTCloseAdapter");
        query_ = load<kmt::QueryAdapterInfoFn>(gdi, "D3DKMTQueryAdapterInfo");
    }
    ~GpuThermals() {
        for (const auto& [luid, adapter] : adapters_) {
            const kmt::CloseAdapter close{.adapter = adapter};
            close_(&close);
        }
        if (nvml_shutdown_ != nullptr) {
            nvml_shutdown_();
        }
    }
    GpuThermals(const GpuThermals&) = delete;
    GpuThermals& operator=(const GpuThermals&) = delete;
    GpuThermals(GpuThermals&&) = delete;
    GpuThermals& operator=(GpuThermals&&) = delete;

    // °C by GPU luid, for those that report one.
    [[nodiscard]] std::map<std::uint64_t, double> read() {
        forget_on_change();
        std::map<std::uint64_t, double> result;
        bool                            missing_nvidia = false;
        for (const auto& gpu : gpus_) {
            if (const auto celsius = from_kernel(gpu.luid); celsius.has_value()) {
                result[gpu.luid] = *celsius;
            } else if (const auto device = nvml_devices_.find(gpu.luid); device != nvml_devices_.end()) {
                if (const auto from_nvml = from_driver(device->second); from_nvml.has_value()) {
                    result[gpu.luid] = *from_nvml;
                }
            } else {
                missing_nvidia |= gpu.vendor == kNvidia;
            }
        }
        // Only once, and only for a card the kernel had nothing for: NVML
        // takes a moment to start.
        if (missing_nvidia && !nvml_tried_) {
            nvml_tried_ = true;
            start_nvml();
        }
        return result;
    }

private:
    static constexpr std::uint32_t kNvidia = 0x10DE;
    // What a driver without KMTQAITYPE_ADAPTERPERFDATA answers.
    static constexpr NTSTATUS kStatusNotImplemented = static_cast<NTSTATUS>(0xC0000002L);
    static constexpr NTSTATUS kStatusInvalidParameter = static_cast<NTSTATUS>(0xC000000DL);
    static constexpr NTSTATUS kStatusNotSupported = static_cast<NTSTATUS>(0xC00000BBL);
    // Reads between looks at the adapter list, while some adapter is
    // remembered as not supporting the query: about a minute.
    static constexpr int kAdapterCheckEvery = 60;

    // A new driver comes with new adapter LUIDs: then every adapter is
    // asked again. Only looked for while there's something to forget.
    void forget_on_change() {
        if (unsupported_.empty() || ++reads_ < kAdapterCheckEvery) {
            return;
        }
        reads_ = 0;
        std::set<std::uint64_t> luids;
        for (const auto& gpu : list_gpus()) {
            luids.insert(gpu.luid);
        }
        if (luids == luids_) {
            return;
        }
        unsupported_.clear();
        for (const auto& [luid, adapter] : adapters_) {
            const kmt::CloseAdapter close{.adapter = adapter};
            close_(&close);
        }
        adapters_.clear();
        luids_ = std::move(luids);
    }

    [[nodiscard]] std::optional<double> from_kernel(std::uint64_t luid) {
        if (open_ == nullptr || close_ == nullptr || query_ == nullptr || unsupported_.contains(luid)) {
            return std::nullopt;
        }
        auto adapter = adapters_.find(luid);
        if (adapter == adapters_.end()) {
            kmt::OpenAdapterFromLuid open{};
            open.luid.LowPart = static_cast<DWORD>(luid & 0xFFFFFFFFU);
            open.luid.HighPart = static_cast<LONG>(luid >> 32U);
            if (open_(&open) < 0) {
                return std::nullopt;
            }
            adapter = adapters_.emplace(luid, open.adapter).first;
        }
        kmt::AdapterPerfData   data{};
        const kmt::QueryAdapterInfo info{
            .adapter = adapter->second, .type = kmt::kAdapterPerfData, .data = &data, .size = sizeof(data)};
        if (const NTSTATUS status = query_(&info); status < 0) {
            const kmt::CloseAdapter close{.adapter = adapter->second};
            close_(&close);
            adapters_.erase(adapter);
            // A driver without the query says so every time: not asked
            // again until the adapters change. Anything else (gone in a
            // driver update or a reset) is opened again next time.
            if (status == kStatusNotSupported || status == kStatusNotImplemented || status == kStatusInvalidParameter) {
                unsupported_.insert(luid);
            }
            return std::nullopt;
        }
        const double celsius = data.temperature / 10.0;
        return plausible_temperature(celsius) ? std::optional(celsius) : std::nullopt;
    }

    [[nodiscard]] std::optional<double> from_driver(nvml::Device device) const {
        unsigned int celsius = 0;
        if (nvml_temperature_ == nullptr ||
            nvml_temperature_(device, nvml::kTemperatureGpu, &celsius) != nvml::kSuccess ||
            !plausible_temperature(celsius)) {
            return std::nullopt;
        }
        return static_cast<double>(celsius);
    }

    // Loads NVML from System32 only (never from a folder someone else could
    // write to: this runs as SYSTEM), and pairs its devices with the DXGI
    // adapters by PCI ids, when that's unambiguous.
    void start_nvml() {
        const HMODULE module = LoadLibraryExW(L"nvml.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        const auto    init = load<nvml::InitFn>(module, "nvmlInit_v2");
        const auto    count = load<nvml::CountFn>(module, "nvmlDeviceGetCount_v2");
        const auto    handle = load<nvml::HandleFn>(module, "nvmlDeviceGetHandleByIndex_v2");
        const auto    pci = load<nvml::PciInfoFn>(module, "nvmlDeviceGetPciInfo_v3");
        const auto    shutdown = load<nvml::ShutdownFn>(module, "nvmlShutdown");
        nvml_temperature_ = load<nvml::TemperatureFn>(module, "nvmlDeviceGetTemperature");
        if (init == nullptr || count == nullptr || handle == nullptr || pci == nullptr || shutdown == nullptr ||
            nvml_temperature_ == nullptr || init() != nvml::kSuccess) {
            spdlog::info("metrics: no GPU temperature from NVML either");
            nvml_temperature_ = nullptr;
            return;
        }
        nvml_shutdown_ = shutdown;
        unsigned int devices = 0;
        if (count(&devices) != nvml::kSuccess) {
            return;
        }
        std::map<std::uint32_t, std::vector<nvml::Device>> by_id;
        for (unsigned int i = 0; i < devices; ++i) {
            nvml::Device  device = nullptr;
            nvml::PciInfo info{};
            if (handle(i, &device) == nvml::kSuccess && pci(device, &info) == nvml::kSuccess) {
                by_id[info.pci_device_id].push_back(device);
            }
        }
        for (const auto& gpu : gpus_) {
            const auto id = (gpu.device << 16U) | gpu.vendor;
            const auto same = std::ranges::count_if(gpus_, [&](const Gpu& other) {
                return ((other.device << 16U) | other.vendor) == id;
            });
            if (const auto found = by_id.find(id); found != by_id.end() && found->second.size() == 1 && same == 1) {
                nvml_devices_[gpu.luid] = found->second.front();
            }
        }
        spdlog::info("metrics: GPU temperature from NVML for {} GPU(s)", nvml_devices_.size());
    }

    std::vector<Gpu>                        gpus_;
    kmt::OpenAdapterFromLuidFn              open_ = nullptr;
    kmt::CloseAdapterFn                     close_ = nullptr;
    kmt::QueryAdapterInfoFn                 query_ = nullptr;
    std::map<std::uint64_t, kmt::Handle>    adapters_;
    std::set<std::uint64_t>                 unsupported_;  // luids whose driver lacks the query
    std::set<std::uint64_t>                 luids_;        // the adapter list last looked at
    int                                     reads_ = 0;
    bool                                    nvml_tried_ = false;
    nvml::ShutdownFn                        nvml_shutdown_ = nullptr;
    nvml::TemperatureFn                     nvml_temperature_ = nullptr;
    std::map<std::uint64_t, nvml::Device>   nvml_devices_;
};

// Each fixed volume's space. Asked every few seconds, not every second:
// a sleeping disk would wake up for it otherwise.
[[nodiscard]] std::vector<VolumeSample> read_volumes() {
    std::vector<VolumeSample> volumes;
    std::array<wchar_t, 512>  drives{};
    const DWORD length = GetLogicalDriveStringsW(static_cast<DWORD>(drives.size()), drives.data());
    if (length == 0 || length > drives.size()) {
        return volumes;
    }
    for (const wchar_t* root = drives.data(); *root != L'\0'; root += std::wcslen(root) + 1) {
        if (GetDriveTypeW(root) != DRIVE_FIXED) {
            continue;
        }
        ULARGE_INTEGER available{};
        ULARGE_INTEGER total{};
        ULARGE_INTEGER free{};
        if (GetDiskFreeSpaceExW(root, &available, &total, &free) == FALSE) {
            continue;
        }
        std::array<wchar_t, MAX_PATH + 1> label{};
        GetVolumeInformationW(root, label.data(), static_cast<DWORD>(label.size()), nullptr, nullptr, nullptr, nullptr,
                              0);
        auto name = win::to_utf8(std::wstring_view(root));
        if (name.ends_with('\\')) {
            name.pop_back();
        }
        volumes.push_back(VolumeSample{
            .name = std::move(name), .label = win::to_utf8(label.data()), .total = total.QuadPart, .free = free.QuadPart});
    }
    return volumes;
}

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

[[nodiscard]] NtQuerySystemInformationFn query_system_information() {
    static const auto function = reinterpret_cast<NtQuerySystemInformationFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
    return function;
}

// SystemProcessInformation into a buffer that grows until it fits.
[[nodiscard]] std::vector<std::byte> process_snapshot() {
    const auto query = query_system_information();
    std::vector<std::byte> buffer(512 * 1024);
    for (int attempt = 0; query != nullptr && attempt < 6; ++attempt) {
        ULONG      needed = 0;
        const auto status = query(SystemProcessInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
        if (status >= 0) {
            return buffer;
        }
        buffer.resize(std::max<std::size_t>(buffer.size() * 2, needed + 64 * 1024));
    }
    return {};
}

// Who a process runs as, "DOMAIN\user" or just "user"; empty when the
// service can't look (protected processes).
[[nodiscard]] std::string process_user(std::uint32_t pid, std::map<std::string, std::string>& names) {
    const win::UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) {
        return {};
    }
    HANDLE raw_token = nullptr;
    if (OpenProcessToken(process.get(), TOKEN_QUERY, &raw_token) == FALSE) {
        return {};
    }
    const win::UniqueHandle token(raw_token);
    std::array<std::byte, 256> buffer{};
    DWORD                      length = 0;
    if (GetTokenInformation(token.get(), TokenUser, buffer.data(), static_cast<DWORD>(buffer.size()), &length) ==
        FALSE) {
        return {};
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR      sid_text = nullptr;
    if (ConvertSidToStringSidW(user->User.Sid, &sid_text) == FALSE) {
        return {};
    }
    const auto key = win::to_utf8(sid_text);
    LocalFree(sid_text);
    if (const auto known = names.find(key); known != names.end()) {
        return known->second;
    }
    std::array<wchar_t, 256> name{};
    std::array<wchar_t, 256> domain{};
    DWORD                    name_size = static_cast<DWORD>(name.size());
    DWORD                    domain_size = static_cast<DWORD>(domain.size());
    SID_NAME_USE             use{};
    std::string              text;
    if (LookupAccountSidW(nullptr, user->User.Sid, name.data(), &name_size, domain.data(), &domain_size, &use) !=
        FALSE) {
        text = win::to_utf8(name.data());
    }
    names.emplace(key, text);
    return text;
}

}  // namespace

// --- Recorder -------------------------------------------------------------------------

struct MetricsRecorder::Impl {
    MetricsConfig config;
    MachineInfo   info;
    std::vector<Gpu> gpus;

    mutable std::mutex mutex;
    std::uint64_t      sequence = 0;
    Sample             latest;
    std::deque<Point>  seconds;  // the last hour
    std::deque<Point>  minutes;  // history_days
    std::int64_t       minute = -1;
    std::array<double, kColumns> minute_sums{};
    int                minute_count = 0;
    std::size_t        records_on_disk = 0;

    // Sampling state, the sampling thread's alone.
    std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> previous_cpu;
    std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> previous_net;  // luid -> rx, tx octets
    std::chrono::steady_clock::time_point previous_net_time{};
    std::vector<VolumeSample> volumes;
    int                       volumes_age = 1000;

    // Process CPU: each one's CPU time at the last listing.
    std::mutex                                                   process_mutex;
    std::map<std::pair<std::uint32_t, std::int64_t>, std::uint64_t> previous_process_time;
    std::chrono::steady_clock::time_point                        previous_process_listing{};
    std::map<std::string, std::string>                           account_names;

    std::jthread thread;

    explicit Impl(MetricsConfig settings) : config(settings) {
        describe();
        load_minutes();
        thread = std::jthread([this](const std::stop_token& stop) { run(stop); });
    }

    void describe() {
        std::array<wchar_t, 256> host{};
        DWORD                    size = static_cast<DWORD>(host.size());
        if (GetComputerNameExW(ComputerNameDnsHostname, host.data(), &size) != FALSE) {
            info.hostname = win::to_utf8(host.data());
        }
        const auto* version_key = LR"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)";
        auto        product = registry_string(HKEY_LOCAL_MACHINE, version_key, L"ProductName");
        const auto  build = registry_string(HKEY_LOCAL_MACHINE, version_key, L"CurrentBuild");
        // Windows 11 still says "Windows 10" here; its builds start at 22000.
        if (product.starts_with("Windows 10") && !build.empty() && std::stoi(build) >= 22000) {
            product.replace(0, 10, "Windows 11");
        }
        const auto display = registry_string(HKEY_LOCAL_MACHINE, version_key, L"DisplayVersion");
        info.os = std::format("{}{}{} (build {})", product, display.empty() ? "" : " ", display, build);

        info.cpu.name = registry_string(HKEY_LOCAL_MACHINE, LR"(HARDWARE\DESCRIPTION\System\CentralProcessor\0)",
                                        L"ProcessorNameString");
        while (!info.cpu.name.empty() && info.cpu.name.back() == ' ') {
            info.cpu.name.pop_back();
        }
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        info.cpu.threads = system.dwNumberOfProcessors;
        info.cpu.cores = physical_cores();

        MEMORYSTATUSEX memory{};
        memory.dwLength = sizeof(memory);
        if (GlobalMemoryStatusEx(&memory) != FALSE) {
            info.memory = memory.ullTotalPhys;
        }
        gpus = list_gpus();
        for (const auto& gpu : gpus) {
            info.gpus.push_back(GpuInfo{.name = gpu.name, .dedicated = gpu.dedicated});
        }
        info.history_days = config.history_days;
        for (const auto& range : kRanges) {
            if (range.seconds || range.span <= static_cast<std::int64_t>(config.history_days) * kSecondsPerDay) {
                info.ranges.emplace_back(range.name);
            }
        }
    }

    // --- the minute history on disk ---

    void load_minutes() {
        const auto read = win::read_protected_file(kMinutesPath);
        if (!read.has_value()) {
            spdlog::warn("metrics: ignoring {}: {}", kMinutesPath.string(), read.error());
            return;
        }
        if (!read->has_value()) {
            return;
        }
        const auto& bytes = **read;
        const auto  since = Clock::to_time_t(Clock::now()) - kept_seconds();
        for (std::size_t offset = 0; offset + kRecordSize <= bytes.size(); offset += kRecordSize) {
            const auto point = decode(bytes.data() + offset);
            if (point.time >= since && (minutes.empty() || point.time > minutes.back().time)) {
                minutes.push_back(point);
            }
        }
        records_on_disk = bytes.size() / kRecordSize;
        spdlog::info("metrics: {} minutes of history", minutes.size());
    }

    [[nodiscard]] std::int64_t kept_seconds() const {
        return static_cast<std::int64_t>(config.history_days) * kSecondsPerDay;
    }

    void append_minute(const Point& point) {
        std::error_code error;
        fs::create_directories(kMetricsDirectory, error);
        // Rewritten from memory now and then, so the file only ever holds
        // about history_days, and never a record from someone else.
        const auto most = static_cast<std::size_t>(config.history_days) * 1440;
        if (records_on_disk + 1 > most + most / 4) {
            rewrite_minutes();
            return;
        }
        const win::UniqueHandle file(CreateFileW(kMinutesPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        const auto record = encode(point);
        DWORD      written = 0;
        if (!file || WriteFile(file.get(), record.data(), static_cast<DWORD>(record.size()), &written, nullptr) == FALSE ||
            written != record.size()) {
            spdlog::warn("metrics: couldn't save to {} (error {})", kMinutesPath.string(), GetLastError());
            return;
        }
        ++records_on_disk;
    }

    void rewrite_minutes() {
        std::string contents;
        contents.reserve(minutes.size() * kRecordSize);
        for (const auto& point : minutes) {
            const auto record = encode(point);
            contents.append(reinterpret_cast<const char*>(record.data()), record.size());
        }
        const auto temporary = fs::path(kMinutesPath).concat(".tmp");
        {
            const win::UniqueHandle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                                     FILE_ATTRIBUTE_NORMAL, nullptr));
            DWORD written = 0;
            if (!file || WriteFile(file.get(), contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) ==
                             FALSE) {
                spdlog::warn("metrics: couldn't rewrite {} (error {})", kMinutesPath.string(), GetLastError());
                return;
            }
        }
        if (MoveFileExW(temporary.c_str(), kMinutesPath.c_str(), MOVEFILE_REPLACE_EXISTING) == FALSE) {
            spdlog::warn("metrics: couldn't replace {} (error {})", kMinutesPath.string(), GetLastError());
            return;
        }
        records_on_disk = minutes.size();
    }

    // --- sampling ---

    void run(const std::stop_token& stop) {
        Counters    counters;
        GpuThermals thermals(gpus);
        std::mutex                  sleep_mutex;
        std::condition_variable_any wake;
        auto next = std::chrono::steady_clock::now();
        // CPU and the rates are differences: the first reading only primes them.
        bool primed = false;
        while (!stop.stop_requested()) {
            counters.collect();
            auto sample = take(counters, thermals);
            if (primed) {
                record(std::move(sample));
            }
            primed = true;
            next += std::chrono::seconds(1);
            const auto now = std::chrono::steady_clock::now();
            if (next < now) {
                next = now;  // fell behind (the PC slept): don't catch up
            }
            std::unique_lock lock(sleep_mutex);
            wake.wait_until(lock, stop, next, [] { return false; });
        }
    }

    [[nodiscard]] Sample take(Counters& counters, GpuThermals& thermals) {
        Sample sample;
        sample.t = unix_millis();
        sample.uptime = GetTickCount64() / 1000;
        read_cpu(sample);
        read_memory(sample);
        read_network(sample);
        sample.disk_read = counters.disk_read();
        sample.disk_write = counters.disk_write();
        if (++volumes_age >= 10) {
            volumes = read_volumes();
            volumes_age = 0;
        }
        sample.volumes = volumes;
        read_gpus(counters, thermals.read(), sample);
        // To a tenth, like the loads.
        if (const auto celsius = counters.thermal_zone(); celsius.has_value()) {
            sample.cpu_temp = std::round(*celsius * 10) / 10;
        }
        return sample;
    }

    void read_cpu(Sample& sample) {
        const auto query = query_system_information();
        if (query == nullptr || info.cpu.threads == 0) {
            return;
        }
        std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> now(info.cpu.threads);
        ULONG returned = 0;
        if (query(SystemProcessorPerformanceInformation, now.data(),
                  static_cast<ULONG>(now.size() * sizeof(now.front())), &returned) < 0) {
            return;
        }
        now.resize(returned / sizeof(now.front()));
        if (previous_cpu.size() == now.size()) {
            std::uint64_t busy_total = 0;
            std::uint64_t all_total = 0;
            for (std::size_t i = 0; i < now.size(); ++i) {
                // KernelTime includes the idle time.
                const auto idle = ticks(now[i].IdleTime) - ticks(previous_cpu[i].IdleTime);
                const auto all = ticks(now[i].KernelTime) + ticks(now[i].UserTime) - ticks(previous_cpu[i].KernelTime) -
                                 ticks(previous_cpu[i].UserTime);
                const auto busy = all > idle ? all - idle : 0;
                sample.cores.push_back(all == 0 ? 0 : std::round(1000.0 * static_cast<double>(busy) / static_cast<double>(all)) / 10);
                busy_total += busy;
                all_total += all;
            }
            sample.cpu = all_total == 0 ? 0 : 100.0 * static_cast<double>(busy_total) / static_cast<double>(all_total);
        }
        previous_cpu = std::move(now);
    }

    static void read_memory(Sample& sample) {
        MEMORYSTATUSEX memory{};
        memory.dwLength = sizeof(memory);
        if (GlobalMemoryStatusEx(&memory) != FALSE) {
            sample.mem_total = memory.ullTotalPhys;
            sample.mem_used = memory.ullTotalPhys - memory.ullAvailPhys;
        }
        PERFORMANCE_INFORMATION performance{};
        if (GetPerformanceInfo(&performance, sizeof(performance)) != FALSE) {
            sample.commit_used = static_cast<std::uint64_t>(performance.CommitTotal) * performance.PageSize;
            sample.commit_limit = static_cast<std::uint64_t>(performance.CommitLimit) * performance.PageSize;
            sample.processes = performance.ProcessCount;
        }
    }

    void read_network(Sample& sample) {
        MIB_IF_TABLE2* table = nullptr;
        if (GetIfTable2(&table) != NO_ERROR) {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - previous_net_time).count();
        std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> current;
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto& row = table->Table[i];
            // One row per real adapter: Windows adds filter and virtual
            // rows for each that would count the same traffic again.
            if (row.InterfaceAndOperStatusFlags.HardwareInterface == FALSE ||
                row.InterfaceAndOperStatusFlags.FilterInterface != FALSE || row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
                row.OperStatus != IfOperStatusUp) {
                continue;
            }
            const auto luid = row.InterfaceLuid.Value;
            current[luid] = {row.InOctets, row.OutOctets};
            const auto before = previous_net.find(luid);
            if (before == previous_net.end() || elapsed <= 0) {
                continue;
            }
            const auto delta = [&](std::uint64_t value, std::uint64_t old) {
                return value >= old ? static_cast<double>(value - old) / elapsed : 0.0;
            };
            AdapterSample adapter{.name = win::to_utf8(row.Alias),
                                  .rx = delta(row.InOctets, before->second.first),
                                  .tx = delta(row.OutOctets, before->second.second)};
            sample.net_rx += adapter.rx;
            sample.net_tx += adapter.tx;
            sample.adapters.push_back(std::move(adapter));
        }
        FreeMibTable(table);
        previous_net = std::move(current);
        previous_net_time = now;
    }

    void read_gpus(const Counters& counters, const std::map<std::uint64_t, double>& temperatures,
                   Sample& sample) const {
        const auto utilisation = counters.gpu_utilisation();
        const auto dedicated = counters.gpu_dedicated();
        const auto shared = counters.gpu_shared();
        const auto value = [](const std::map<std::uint64_t, double>& map, std::uint64_t luid) {
            const auto found = map.find(luid);
            return found == map.end() ? 0.0 : found->second;
        };
        for (const auto& gpu : gpus) {
            sample.gpus.push_back(GpuSample{.name = gpu.name,
                                            .util = std::round(value(utilisation, gpu.luid) * 10) / 10,
                                            .dedicated_used = static_cast<std::uint64_t>(value(dedicated, gpu.luid)),
                                            .dedicated_total = gpu.dedicated,
                                            .shared_used = static_cast<std::uint64_t>(value(shared, gpu.luid)),
                                            .temp = std::nullopt});
            if (const auto found = temperatures.find(gpu.luid); found != temperatures.end()) {
                sample.gpus.back().temp = std::round(found->second * 10) / 10;
            }
        }
    }

    void record(Sample sample) {
        Point point{.time = sample.t / 1000};
        point.values.at(kCpu) = sample.cpu;
        point.values.at(kMem) = static_cast<double>(sample.mem_used);
        for (const auto& gpu : sample.gpus) {
            point.values.at(kGpu) = std::max(point.values.at(kGpu), gpu.util);
            point.values.at(kVram) += static_cast<double>(gpu.dedicated_used);
        }
        point.values.at(kRx) = sample.net_rx;
        point.values.at(kTx) = sample.net_tx;
        point.values.at(kRead) = sample.disk_read;
        point.values.at(kWrite) = sample.disk_write;
        sample.cpu = std::round(sample.cpu * 10) / 10;
        for (auto* rate : {&sample.net_rx, &sample.net_tx, &sample.disk_read, &sample.disk_write}) {
            *rate = std::round(*rate);
        }
        for (auto& adapter : sample.adapters) {
            adapter.rx = std::round(adapter.rx);
            adapter.tx = std::round(adapter.tx);
        }

        const std::lock_guard lock(mutex);
        latest = std::move(sample);
        ++sequence;
        seconds.push_back(point);
        while (seconds.size() > kSecondsKept) {
            seconds.pop_front();
        }
        // A minute's average once it's over.
        const auto this_minute = point.time - point.time % 60;
        if (this_minute != minute && minute_count > 0) {
            Point average{.time = minute};
            for (std::size_t i = 0; i < kColumns; ++i) {
                average.values.at(i) = minute_sums.at(i) / minute_count;
            }
            minutes.push_back(average);
            const auto since = point.time - kept_seconds();
            while (!minutes.empty() && minutes.front().time < since) {
                minutes.pop_front();
            }
            append_minute(average);
            minute_sums = {};
            minute_count = 0;
        }
        minute = this_minute;
        for (std::size_t i = 0; i < kColumns; ++i) {
            minute_sums.at(i) += point.values.at(i);
        }
        ++minute_count;
    }

    // --- processes ---

    [[nodiscard]] ProcessList list_processes() {
        const auto      snapshot = process_snapshot();
        const std::lock_guard lock(process_mutex);
        ProcessList list;
        list.t = unix_millis();
        const auto  now = std::chrono::steady_clock::now();
        const double wall = std::chrono::duration<double>(now - previous_process_listing).count();
        const bool   first = previous_process_time.empty();
        const double capacity = wall * kTicksPerSecond * std::max<std::uint32_t>(info.cpu.threads, 1);
        std::map<std::pair<std::uint32_t, std::int64_t>, std::uint64_t> times;
        for (std::size_t offset = 0; !snapshot.empty();) {
            const auto* entry = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(snapshot.data() + offset);
            const auto  pid = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entry->UniqueProcessId));
            if (pid != 0) {  // the idle "process": its CPU is what's left
                const auto created = entry->CreateTime.QuadPart;
                const auto key = std::make_pair(pid, static_cast<std::int64_t>(created));
                const auto cpu_time = ticks(entry->KernelTime) + ticks(entry->UserTime);
                times[key] = cpu_time;
                double cpu = 0;
                if (const auto before = previous_process_time.find(key);
                    !first && before != previous_process_time.end() && capacity > 0 && cpu_time >= before->second) {
                    cpu = std::round(1000.0 * static_cast<double>(cpu_time - before->second) / capacity) / 10;
                }
                std::string name = entry->ImageName.Buffer != nullptr
                                       ? win::to_utf8(std::wstring_view(entry->ImageName.Buffer, entry->ImageName.Length / sizeof(wchar_t)))
                                       : std::string(pid == 4 ? "System" : "");
                list.processes.push_back(ProcessRow{
                    .pid = pid,
                    .parent = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entry->InheritedFromUniqueProcessId)),
                    .name = std::move(name),
                    .user = process_user(pid, account_names),
                    .cpu = cpu,
                    .memory = entry->VirtualMemoryCounters.WorkingSetSize,
                    .private_bytes = entry->PrivatePageCount,
                    .threads = entry->NumberOfThreads,
                    .handles = entry->HandleCount,
                    .session = entry->SessionId,
                    .started = created > 0 ? (created - kFiletimeUnixEpoch) / 10000 : 0,
                });
            }
            if (entry->NextEntryOffset == 0) {
                break;
            }
            offset += entry->NextEntryOffset;
        }
        previous_process_time = std::move(times);
        previous_process_listing = now;
        return list;
    }
};

MetricsRecorder::MetricsRecorder(MetricsConfig config) : impl_(std::make_unique<Impl>(config)) {}

MetricsRecorder::~MetricsRecorder() = default;

std::uint64_t MetricsRecorder::sequence() const {
    const std::lock_guard lock(impl_->mutex);
    return impl_->sequence;
}

std::string MetricsRecorder::info_json() const {
    return glz::write_json(impl_->info).value_or("{}");
}

std::string MetricsRecorder::sample_json() const {
    const std::lock_guard lock(impl_->mutex);
    return glz::write_json(impl_->latest).value_or("{}");
}

std::optional<std::string> MetricsRecorder::history_json(std::string_view range) const {
    const auto* spec = std::ranges::find(kRanges, range, &RangeSpec::name);
    if (spec == kRanges.end() || std::ranges::find(impl_->info.ranges, range) == impl_->info.ranges.end()) {
        return std::nullopt;
    }
    const auto since = Clock::to_time_t(Clock::now()) - spec->span;
    const std::lock_guard lock(impl_->mutex);
    return glz::write_json(downsample(*spec, spec->seconds ? impl_->seconds : impl_->minutes, since)).value_or("{}");
}

std::string MetricsRecorder::processes_json() {
    return glz::write_json(impl_->list_processes()).value_or("{}");
}

// --- Channel -------------------------------------------------------------------------------

struct MetricsChannel::Impl {
    MetricsRecorder& recorder;
    ViewerHub&       hub;

    std::mutex                                           mutex;
    std::condition_variable_any                          wake;
    std::deque<std::pair<std::uint64_t, ChannelMessage>> requests;
    std::set<std::uint64_t>                              subscribed;
    std::jthread                                         thread;

    Impl(MetricsRecorder& source, ViewerHub& viewers) : recorder(source), hub(viewers) {
        thread = std::jthread([this](const std::stop_token& stop) { run(stop); });
    }

    void send(std::uint64_t viewer, std::uint8_t op, std::string body, std::string header = "{}") {
        ChannelMessage message;
        message.op = op;
        message.header = std::move(header);
        message.data.resize(body.size());
        std::memcpy(message.data.data(), body.data(), body.size());
        if (!hub.send_metrics(viewer, message)) {
            const std::lock_guard lock(mutex);
            subscribed.erase(viewer);
        }
    }

    void error(std::uint64_t viewer, std::string text) {
        send(viewer, metrics_op::error, {}, glz::write_json(ErrorHeader{.message = std::move(text)}).value_or("{}"));
    }

    void answer(std::uint64_t viewer, const ChannelMessage& message) {
        switch (message.op) {
            case metrics_op::subscribe: {
                {
                    const std::lock_guard lock(mutex);
                    subscribed.insert(viewer);
                }
                send(viewer, metrics_op::info, recorder.info_json());
                if (recorder.sequence() > 0) {
                    send(viewer, metrics_op::sample, recorder.sample_json());
                }
                break;
            }
            case metrics_op::unsubscribe: {
                const std::lock_guard lock(mutex);
                subscribed.erase(viewer);
                break;
            }
            case metrics_op::history: {
                RangeHeader header;
                if (glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header)) {
                    error(viewer, "malformed history request");
                    break;
                }
                if (auto body = recorder.history_json(header.range); body.has_value()) {
                    send(viewer, metrics_op::history_data, std::move(*body));
                } else {
                    error(viewer, std::format("no history for \"{}\" on this machine", header.range));
                }
                break;
            }
            case metrics_op::processes:
                send(viewer, metrics_op::process_list, recorder.processes_json());
                break;
            default:
                error(viewer, "unknown request");
        }
    }

    void run(const std::stop_token& stop) {
        std::uint64_t sent = recorder.sequence();
        while (!stop.stop_requested()) {
            std::deque<std::pair<std::uint64_t, ChannelMessage>> work;
            std::vector<std::uint64_t>                           watching;
            {
                std::unique_lock lock(mutex);
                wake.wait_for(lock, stop, std::chrono::milliseconds(200), [&] { return !requests.empty(); });
                work.swap(requests);
                watching.assign(subscribed.begin(), subscribed.end());
            }
            for (auto& [viewer, message] : work) {
                answer(viewer, message);
            }
            const auto latest = recorder.sequence();
            if (latest != sent && !watching.empty()) {
                const auto body = recorder.sample_json();
                for (const auto viewer : watching) {
                    send(viewer, metrics_op::sample, body);
                }
            }
            sent = latest;
        }
    }
};

MetricsChannel::MetricsChannel(MetricsRecorder& recorder, ViewerHub& hub)
    : impl_(std::make_unique<Impl>(recorder, hub)) {}

MetricsChannel::~MetricsChannel() = default;

void MetricsChannel::handle(std::uint64_t viewer, ChannelMessage message) {
    {
        const std::lock_guard lock(impl_->mutex);
        // A viewer can't pile up work: a handful of requests in flight.
        if (impl_->requests.size() >= 32) {
            return;
        }
        impl_->requests.emplace_back(viewer, std::move(message));
    }
    impl_->wake.notify_one();
}

void MetricsChannel::drop_viewer(std::uint64_t viewer) {
    const std::lock_guard lock(impl_->mutex);
    impl_->subscribed.erase(viewer);
    std::erase_if(impl_->requests, [&](const auto& request) { return request.first == viewer; });
}

}  // namespace hawk::service
