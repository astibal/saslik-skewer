#include "app_egress_guard.hpp"
#include <fwpmu.h>
#include <array>
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <system_error>

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
        FwpmFreeMemory0(reinterpret_cast<void**>(&pointer));
    }
};
template <typename T> using WfpObject = std::unique_ptr<T, WfpFree>;

class Engine final {
public:
    Engine() { check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &handle), "Open WFP"); }
    ~Engine() { FwpmEngineClose0(handle); }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    HANDLE handle{};
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
    FWP_BYTE_BLOB* raw_image{};
    check(FwpmGetAppIdFromFileName0(executable_.c_str(), &raw_image), "Resolve application identity");
    WfpObject<FWP_BYTE_BLOB> image(raw_image);
    Engine engine;
    Transaction transaction(engine.handle);

    FWPM_SUBLAYER0* raw_sublayer{};
    const auto sub_error = FwpmSubLayerGetByKey0(engine.handle, &id_, &raw_sublayer);
    WfpObject<FWPM_SUBLAYER0> sublayer(raw_sublayer);
    if (sub_error != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) {
        check(sub_error, "Read guard sublayer");
        if (sublayer->flags != persistent || !sameBlob(sublayer->providerData, *image)) {
            throw std::runtime_error("Guard policy ID belongs to a different policy; refusing mutation");
        }
    }

    const std::array layers{connect4, connect6};
    std::array<GUID, 2> keys{id_, id_};
    std::array<bool, 2> present{};
    for (size_t index = 0; index != keys.size(); ++index) {
        keys[index].Data1 ^= static_cast<ULONG>(index + 1);
        FWPM_FILTER0* raw_filter{};
        const auto error = FwpmFilterGetByKey0(engine.handle, &keys[index], &raw_filter);
        WfpObject<FWPM_FILTER0> filter(raw_filter);
        if (error == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) {
            continue;
        }
        check(error, "Read guard filter");
        if (!matches(*filter, layers[index], id_, *image)) {
            throw std::runtime_error("Guard filter differs from requested policy; refusing mutation (flags=" +
                                     std::to_string(filter->flags) +
                                     ", action=" + std::to_string(filter->action.type) +
                                     ", conditions=" + std::to_string(filter->numFilterConditions) + ")");
        }
        present[index] = true;
    }
    const bool complete = sublayer && present[0] && present[1];
    const bool any = sublayer || present[0] || present[1];
    if (operation != Operation::Release && any && !complete) {
        throw std::runtime_error("Incomplete guard; protection cannot be reported as active");
    }
    if (operation == Operation::Arm && !complete) {
        FWPM_SUBLAYER0 layer{};
        layer.subLayerKey = id_;
        layer.displayData.name = const_cast<wchar_t*>(policy_name);
        layer.flags = persistent;
        layer.providerData = *image;
        layer.weight = 0x8000;
        check(FwpmSubLayerAdd0(engine.handle, &layer, nullptr), "Add persistent guard sublayer");
        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey = app_id;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.byteBlob = image.get();
        for (size_t index = 0; index != keys.size(); ++index) {
            FWPM_FILTER0 filter{};
            filter.filterKey = keys[index];
            filter.displayData.name = const_cast<wchar_t*>(policy_name);
            filter.flags = persistent;
            filter.layerKey = layers[index];
            filter.subLayerKey = id_;
            filter.action.type = FWP_ACTION_BLOCK;
            filter.numFilterConditions = 1;
            filter.filterCondition = &condition;
            check(FwpmFilterAdd0(engine.handle, &filter, nullptr, nullptr), "Add persistent guard filter");
        }
    }
    if (operation == Operation::Release) {
        // Delete only verified objects, atomically. Never enumerate/delete by name.
        for (size_t index = 0; index != keys.size(); ++index) {
            if (present[index]) {
                check(FwpmFilterDeleteByKey0(engine.handle, &keys[index]), "Release guard filter");
            }
        }
        if (sublayer) {
            check(FwpmSubLayerDeleteByKey0(engine.handle, &id_), "Release guard sublayer");
        }
    }
    transaction.commit();
    return complete;
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
