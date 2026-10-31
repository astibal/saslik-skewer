// Build-only WDM prototype. No IOCTL interface, packet injection or permit path.
// WDK's NDIS structures intentionally contain explicit alignment padding.
#pragma warning(push)
#pragma warning(disable : 4324)
#include <ntifs.h>
#include <fwpsk.h>
#pragma warning(pop)
#include "decision.hpp"

namespace {
// These identifiers must be shared with the future explicitly scoped filter
// installer. Registering a callout alone installs no traffic-matching filter.
const GUID callout4 = {0x31756d84, 0xa4cc, 0x44bf, {0xa7, 0xdf, 0x38, 0x7b, 0xf2, 0xd8, 0x5d, 0x31}};
const GUID callout6 = {0x671ca684, 0xc090, 0x4673, {0x97, 0xda, 0x12, 0x43, 0xee, 0x49, 0x0d, 0x2c}};

struct State {
    PDEVICE_OBJECT device;
    PEPROCESS target;
    HANDLE pid;
    volatile LONG active;
    bool process_notify;
    UINT32 v4, v6;
};
State state{}; // Nonpaged, immutable identity while callbacks are registered.

NTSTATUS readQword(HANDLE key, PCWSTR name, ULONGLONG& value) {
    UNICODE_STRING value_name;
    RtlInitUnicodeString(&value_name, name);
    alignas(KEY_VALUE_PARTIAL_INFORMATION) UCHAR storage[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 8]{};
    ULONG returned{};
    auto status =
        ZwQueryValueKey(key, &value_name, KeyValuePartialInformation, storage, sizeof(storage), &returned);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    auto info = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>(storage);
    if (info->Type != REG_QWORD || info->DataLength != sizeof(value)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(&value, info->Data, sizeof(value));
    return STATUS_SUCCESS;
}

NTSTATUS selectTarget(PUNICODE_STRING registry_path) {
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    HANDLE service{};
    auto status = ZwOpenKey(&service, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNICODE_STRING parameters;
    RtlInitUnicodeString(&parameters, L"Parameters");
    InitializeObjectAttributes(&attributes, &parameters, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, service,
                               nullptr);
    HANDLE key{};
    status = ZwOpenKey(&key, KEY_READ, &attributes);
    ZwClose(service);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ULONGLONG pid{}, created{};
    status = readQword(key, L"TargetPid", pid);
    if (NT_SUCCESS(status)) {
        status = readQword(key, L"TargetCreationTime", created);
    }
    ZwClose(key);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!pid || pid > MAXULONG || !created) {
        return STATUS_INVALID_PARAMETER;
    }
    state.pid = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    status = PsLookupProcessByProcessId(state.pid, &state.target);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (static_cast<ULONGLONG>(PsGetProcessCreateTimeQuadPart(state.target)) != created) {
        return STATUS_INVALID_CID;
    }
    return STATUS_SUCCESS;
}

void processChanged(PEPROCESS process, HANDLE, PPS_CREATE_NOTIFY_INFO create) {
    // Exit retires the selected instance, not the PID's eventual next occupant.
    // There is no lock, allocation, pageable API or user-mode round trip here.
    if (!create && process == state.target) {
        InterlockedExchange(&state.active, 0);
    }
}

void classify(const FWPS_INCOMING_VALUES0* values, const FWPS_INCOMING_METADATA_VALUES0* metadata, void*,
              const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0* output) {
    // A management filter must select the intended image and ALE layer. Never
    // install a conditionless terminating filter pointing at this prototype.
    const bool layer = values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ||
                       values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6;
    const bool has_pid = (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0;
    const auto decision =
        skewer::ale::decide({(output->rights & FWPS_RIGHT_ACTION_WRITE) != 0, layer, has_pid,
                             InterlockedCompareExchange(&state.active, 0, 0) != 0,
                             has_pid ? metadata->processId : 0, reinterpret_cast<ULONG_PTR>(state.pid)});
    if (decision == skewer::ale::Decision::Preserve) {
        return;
    }
    if (decision == skewer::ale::Decision::Block) {
        output->actionType = FWP_ACTION_BLOCK;
        output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    // CONTINUE is not PERMIT: do not override another provider's protection.
    output->actionType = FWP_ACTION_CONTINUE;
}

NTSTATUS notify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER0*) {
    return STATUS_SUCCESS;
}

bool rollback() {
    // No flow contexts are created by this prototype. Unregister synchronizes
    // callbacks before the process reference and device can be released.
    if (state.v6) {
        if (!NT_SUCCESS(FwpsCalloutUnregisterById0(state.v6))) {
            return false;
        }
        state.v6 = 0;
    }
    if (state.v4) {
        if (!NT_SUCCESS(FwpsCalloutUnregisterById0(state.v4))) {
            return false;
        }
        state.v4 = 0;
    }
    if (state.process_notify) {
        if (!NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(processChanged, TRUE))) {
            return false;
        }
        state.process_notify = false;
    }
    if (state.target) {
        ObDereferenceObject(state.target);
        state.target = nullptr;
    }
    if (state.device) {
        IoDeleteDevice(state.device);
        state.device = nullptr;
    }
    return true;
}

NTSTATUS registerCallout(const GUID& id, UINT32& runtime_id) {
    FWPS_CALLOUT0 callout{};
    callout.calloutKey = id;
    callout.classifyFn = classify;
    callout.notifyFn = notify;
    return FwpsCalloutRegister0(state.device, &callout, &runtime_id);
}
} // namespace

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path) {
    auto status = selectTarget(registry_path);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&state.active, 1);
        status = PsSetCreateProcessNotifyRoutineEx(processChanged, FALSE);
        state.process_notify = NT_SUCCESS(status);
    }
    // Close the race where the selected process exited before notification
    // registration. Only retire here; never reactivate after an exit callback.
    if (NT_SUCCESS(status) && PsGetProcessExitStatus(state.target) != STATUS_PENDING) {
        InterlockedExchange(&state.active, 0);
        status = STATUS_PROCESS_IS_TERMINATING;
    }
    if (NT_SUCCESS(status)) {
        status = IoCreateDevice(driver, 0, nullptr, FILE_DEVICE_NETWORK, 0, FALSE, &state.device);
    }
    if (NT_SUCCESS(status)) {
        status = registerCallout(callout4, state.v4);
    }
    if (NT_SUCCESS(status)) {
        status = registerCallout(callout6, state.v6);
    }
    if (!NT_SUCCESS(status)) {
        if (rollback()) {
            return status;
        }
        // A callback could not be unregistered. Returning failure would unload
        // its executable code underneath the kernel. Keep the image resident,
        // without an unload entry, and require reboot of the disposable VM.
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                   "Skewer ALE prototype: rollback failed; reboot required\n");
        return STATUS_SUCCESS;
    }
    state.device->Flags &= ~DO_DEVICE_INITIALIZING;
    // Deliberately no DriverUnload in this build-only prototype. Safe dynamic
    // filter removal/unregistration needs its own tested lifecycle protocol.
    return STATUS_SUCCESS;
}
