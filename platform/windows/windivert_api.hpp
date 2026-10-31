#pragma once
#include <windows.h>
#include <cstdint>

// WinDivert 2.2's MinGW compatibility macros otherwise leak into later C++
// standard headers (__in/__out are also implementation variable names there).
// Preserve the caller's environment rather than requiring fragile include order.
#pragma push_macro("__in")
#pragma push_macro("__in_opt")
#pragma push_macro("__out")
#pragma push_macro("__out_opt")
#pragma push_macro("__inout")
#pragma push_macro("__inout_opt")
#pragma push_macro("INT8")
#pragma push_macro("UINT8")
#pragma push_macro("INT16")
#pragma push_macro("UINT16")
#pragma push_macro("INT32")
#pragma push_macro("UINT32")
#pragma push_macro("INT64")
#pragma push_macro("UINT64")
#include <windivert.h>
#pragma pop_macro("UINT64")
#pragma pop_macro("INT64")
#pragma pop_macro("UINT32")
#pragma pop_macro("INT32")
#pragma pop_macro("UINT16")
#pragma pop_macro("INT16")
#pragma pop_macro("UINT8")
#pragma pop_macro("INT8")
#pragma pop_macro("__inout_opt")
#pragma pop_macro("__inout")
#pragma pop_macro("__out_opt")
#pragma pop_macro("__out")
#pragma pop_macro("__in_opt")
#pragma pop_macro("__in")
