#include "app_egress_guard.hpp"
#include <fwpmu.h>
#include <array>
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace skewer::windows::traffic {
namespace {
// Stable SDK ABI values omitted by older MinGW headers. Keep these local, not
// replacement SDK macros. Source: Microsoft's win32metadata fwpmu/fwpmtypes.h.
constexpr GUID connect4{0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
constexpr GUID connect6{0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
constexpr GUID app_id{0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
constexpr UINT32 persistent = 1;
constexpr UINT32 indexed = 0x40;
constexpr wchar_t policy_name[] = L"Skewer application image egress block";

void check(DWORD error, const char* operation) {
    if (error != ERROR_SUCCESS) {
        throw std::system_error(static_cast<int>(error), std::system_category(), operation);
    }
}

struct WfpFree {
    template <typename T> void operator()(T* pointer) const {
        void* allocation = pointer;
        FwpmFreeMemory0(&allocation);
    }
};
template <typename T> using WfpObject = std::unique_ptr<T, WfpFree>;

class Engine final {
public:
    Engine() { check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &handle_), "Open WFP"); }
    ~Engine() { FwpmEngineClose0(handle_); }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    HANDLE handle() const { return handle_; }

private:
    HANDLE handle_{};
};

class Transaction final {
public:
    explicit Transaction(HANDLE engine) : engine_(engine) {
        check(FwpmTransactionBegin0(engine_, 0), "Begin WFP transaction");
    }
    ~Transaction() {
        if (!committed_) {
            FwpmTransactionAbort0(engine_);
        }
    }
    void commit() {
        check(FwpmTransactionCommit0(engine_), "Commit WFP transaction");
        committed_ = true;
    }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

private:
    HANDLE engine_;
    bool committed_{};
};

bool sameBlob(const FWP_BYTE_BLOB& left, const FWP_BYTE_BLOB& right) {
    return left.size == right.size && left.data && right.data &&
           std::memcmp(left.data, right.data, left.size) == 0;
}

bool matches(const FWPM_FILTER0& filter, const GUID& layer, const GUID& policy, const FWP_BYTE_BLOB& image) {
    // BFE adds INDEXED when it indexes this condition. It is a storage detail,
    // not a policy change; still reject all other unexpected semantic flags.
    if ((filter.flags & ~indexed) != persistent || filter.action.type != FWP_ACTION_BLOCK ||
        !IsEqualGUID(filter.layerKey, layer) || !IsEqualGUID(filter.subLayerKey, policy) ||
        filter.numFilterConditions != 1 || !filter.filterCondition) {
        return false;
    }
    const auto& condition = *filter.filterCondition;
    return IsEqualGUID(condition.fieldKey, app_id) && condition.matchType == FWP_MATCH_EQUAL &&
           condition.conditionValue.type == FWP_BYTE_BLOB_TYPE && condition.conditionValue.byteBlob &&
           sameBlob(*condition.conditionValue.byteBlob, image);
}
WfpObject<FWP_BYTE_BLOB> resolveImage(const std::wstring& executable) {
    FWP_BYTE_BLOB* raw_image{};
    const auto error = FwpmGetAppIdFromFileName0(executable.c_str(), &raw_image);
    WfpObject<FWP_BYTE_BLOB> image(raw_image);
    check(error, "Resolve application identity");
    return image;
}

struct FilterSpec {
    GUID key;
    GUID layer;
};
using FilterSpecs = std::array<FilterSpec, 2>;

FilterSpecs filterSpecs(const GUID& policy) {
    FilterSpecs specs{{{policy, connect4}, {policy, connect6}}};
    // Stable derivation is part of the persisted policy format. Changing this
    // mapping would strand filters created by an older process/build.
    specs[0].key.Data1 ^= 1;
    specs[1].key.Data1 ^= 2;
    return specs;
}

struct PolicyState {
    bool sublayer{};
    std::array<bool, 2> filters{};

    bool complete() const { return sublayer && filters[0] && filters[1]; }
    bool empty() const { return !sublayer && !filters[0] && !filters[1]; }
};

bool inspectSublayer(HANDLE engine, const GUID& policy, const FWP_BYTE_BLOB& image) {
    FWPM_SUBLAYER0* raw_sublayer{};
    const auto error = FwpmSubLayerGetByKey0(engine, &policy, &raw_sublayer);
    WfpObject<FWPM_SUBLAYER0> sublayer(raw_sublayer);
    if (error == static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) {
        return false;
    }
    check(error, "Read guard sublayer");
    if (sublayer->flags != persistent || !sameBlob(sublayer->providerData, image)) {
        throw std::runtime_error("Guard policy ID belongs to a different policy; refusing mutation");
    }
    return true;
}

bool inspectFilter(HANDLE engine, const GUID& policy, const FilterSpec& spec, const FWP_BYTE_BLOB& image) {
    FWPM_FILTER0* raw_filter{};
    const auto error = FwpmFilterGetByKey0(engine, &spec.key, &raw_filter);
    WfpObject<FWPM_FILTER0> filter(raw_filter);
    if (error == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) {
        return false;
    }
    check(error, "Read guard filter");
    if (!matches(*filter, spec.layer, policy, image)) {
        throw std::runtime_error("Guard filter differs from requested policy; refusing mutation (flags=" +
                                 std::to_string(filter->flags) +
                                 ", action=" + std::to_string(filter->action.type) +
                                 ", conditions=" + std::to_string(filter->numFilterConditions) + ")");
    }
    return true;
}

PolicyState inspectPolicy(HANDLE engine, const GUID& policy, const FilterSpecs& specs,
                          const FWP_BYTE_BLOB& image) {
    PolicyState state;
    state.sublayer = inspectSublayer(engine, policy, image);
    for (size_t index = 0; index != specs.size(); ++index) {
        state.filters[index] = inspectFilter(engine, policy, specs[index], image);
    }
    return state;
}

void addPolicy(HANDLE engine, const GUID& policy, const FilterSpecs& specs, FWP_BYTE_BLOB& image) {
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = policy;
    sublayer.displayData.name = const_cast<wchar_t*>(policy_name);
    sublayer.flags = persistent;
    sublayer.providerData = image;
    sublayer.weight = 0x8000;
    check(FwpmSubLayerAdd0(engine, &sublayer, nullptr), "Add persistent guard sublayer");

    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey = app_id;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = &image;
    for (const auto& spec : specs) {
        FWPM_FILTER0 filter{};
        filter.filterKey = spec.key;
        filter.displayData.name = const_cast<wchar_t*>(policy_name);
        filter.flags = persistent;
        filter.layerKey = spec.layer;
        filter.subLayerKey = policy;
        filter.action.type = FWP_ACTION_BLOCK;
        filter.numFilterConditions = 1;
        filter.filterCondition = &condition;
        check(FwpmFilterAdd0(engine, &filter, nullptr, nullptr), "Add persistent guard filter");
    }
}

void removePolicy(HANDLE engine, const GUID& policy, const FilterSpecs& specs, const PolicyState& state) {
    // The caller inspected every object in this same transaction. Delete only
    // verified keys, never objects found by a display-name search.
    for (size_t index = 0; index != specs.size(); ++index) {
        if (state.filters[index]) {
            check(FwpmFilterDeleteByKey0(engine, &specs[index].key), "Release guard filter");
        }
    }
    if (state.sublayer) {
        check(FwpmSubLayerDeleteByKey0(engine, &policy), "Release guard sublayer");
    }
}
} // namespace

AppImageBlock::AppImageBlock(GUID policy_id, std::wstring executable)
    : id_(policy_id), executable_(std::move(executable)) {
    const GUID empty{};
    if (IsEqualGUID(id_, empty) || executable_.find(L'\0') != std::wstring::npos ||
        !std::filesystem::path(executable_).is_absolute()) {
        throw std::invalid_argument("Guard requires a nonzero policy ID and absolute executable path");
    }
}

bool AppImageBlock::perform(Operation operation) const {
    const auto image = resolveImage(executable_);
    const auto specs = filterSpecs(id_);
    Engine engine;
    // Inspection and mutation share a transaction, preventing a concurrent
    // policy owner from replacing objects between verification and deletion.
    Transaction transaction(engine.handle());
    const auto state = inspectPolicy(engine.handle(), id_, specs, *image);
    if (operation != Operation::Release && !state.empty() && !state.complete()) {
        throw std::runtime_error("Incomplete guard; protection cannot be reported as active");
    }
    switch (operation) {
    case Operation::Inspect:
        break;
    case Operation::Arm:
        if (state.empty()) {
            addPolicy(engine.handle(), id_, specs, *image);
        }
        break;
    case Operation::Release:
        removePolicy(engine.handle(), id_, specs, state);
        break;
    }
    transaction.commit();
    return state.complete();
}

void AppImageBlock::arm() const {
    perform(Operation::Arm);
}
bool AppImageBlock::installed() const {
    return perform(Operation::Inspect);
}
void AppImageBlock::release() const {
    perform(Operation::Release);
}

} // namespace skewer::windows::traffic
