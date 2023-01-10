/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */
#ifndef  INCLUDE_OPC_MAPS_H_
#define  INCLUDE_OPC_MAPS_H_
/**
 * This file contains various maps that are reported as uncovered lines by gcov.
 * It is excluded from GCOV analysis.
 */
// System includes
#include <map>
#include <string>

extern "C" {
// S2OPC Headers
#include "sopc_builtintypes.h"
#include "libs2opc_server_config_custom.h"
}

namespace {
using StringToOpcTypes = std::map<std::string, SOPC_BuiltinId>;
const StringToOpcTypes pivto2Opc_Types{
    {"opcua_sps", SOPC_Boolean_Id},
    {"opcua_dps", SOPC_String_Id},
    {"opcua_mvi", SOPC_Int32_Id},
    {"opcua_mvf", SOPC_Float_Id},
    {"opcua_spc", SOPC_Boolean_Id},
    {"opcua_dpc", SOPC_Byte_Id},
    {"opcua_inc", SOPC_Int32_Id},
    {"opcua_apc", SOPC_Float_Id},
    {"opcua_bsc", SOPC_Null_Id},
};

using PolicyMap = std::map<std::string, SOPC_SecurityPolicy_URI>;
static const PolicyMap policiesMap {
    {"None", SOPC_SecurityPolicy_None},
    {"Basic256", SOPC_SecurityPolicy_Basic256},
    {"Basic256Sha256", SOPC_SecurityPolicy_Basic256Sha256},
    {"Aes128Sha256RsaOaep", SOPC_SecurityPolicy_Aes128Sha256RsaOaep},
    {"Aes128Sha256RsaPss", SOPC_SecurityPolicy_Aes256Sha256RsaPss}
};

using ModeMap = std::map<std::string, SOPC_SecurityModeMask>;
static const ModeMap modesMap {
    {"NONE", SOPC_SecurityModeMask_None},
    {"SIGN", SOPC_SecurityModeMask_Sign},
    {"SIGNANDENCRYPT", SOPC_SecurityModeMask_SignAndEncrypt}
};

using LevelMap = std::map<std::string, SOPC_Log_Level>;
// Note:  static_cast is only used to help editor parser.
static const LevelMap levelsMap {
    {"DEBUG", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_DEBUG)},
    {"INFO", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_INFO)},
    {"WARNING", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_WARNING)},
    {"ERROR", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_ERROR)}
};

}   // namespace

#endif  // INCLUDE_OPC_MAPS_H_
