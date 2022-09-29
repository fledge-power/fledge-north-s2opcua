/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

/// Project includes
#include "opcua_server_addrspace.h"
#include "opcua_server.h"
#include "opcua_server_config.h"

// System headers
#include <unistd.h>
#include <sys/stat.h>
#include <exception>
#include <chrono>
#include <thread>

// Fledge headers
#include "datapoint.h"

extern "C" {
// S2OPC Headers
#include "sopc_atomic.h"
#include "sopc_common.h"
#include "sopc_macros.h"
#include "sopc_builtintypes.h"
#include "sopc_encodeabletype.h"
#include "opcua_statuscodes.h"
#include "sopc_log_manager.h"
#include "sopc_pki.h"
#include "sopc_pki_stack.h"
#include "sopc_logger.h"
#include "sopc_types.h"
#include "sopc_mem_alloc.h"
// From S2OPC "frontend"
#include "libs2opc_common_config.h"
#include "libs2opc_server.h"
#include "libs2opc_server_config.h"
#include "libs2opc_server_config_custom.h"
#include "libs2opc_request_builder.h"
// From S2OPC "clientserver"
#include "sopc_toolkit_config.h"
#include "sopc_user_manager.h"
#include "embedded/sopc_addspace_loader.h"
#include "sopc_toolkit_async_api.h"
}

// Include generated JSON file
/* See "mkjson" and "default_config.json"
   Note that the source file syntax supports enhanced features so as to
   allow a visual intuitive edition:
   - Using simple quotes inside strings is actually replaced by \"(typical usage for JSON)
        This is useful for filling in JSON content without needing backslashing everything
        e.g.:  "default" : "{ 'name' : 'value'} ",
   - As a consequence the character ' cannot be used inside strings. The escape sequence "\x27" can be used if required
*/
#include "default_config.inc"

/**************************************************************************/
// Reminder: all callbacks/events called from s2opc must be enclosed in
// extern "C" context!
extern "C" {

static void SOPC_LocalServiceAsyncRespCallback(SOPC_EncodeableType* encType, void* response, uintptr_t appContext) {
    if (appContext == 0) return;

    s2opc_north::OPCUA_Server& srv(*reinterpret_cast<s2opc_north::OPCUA_Server*>(appContext));
    if (encType == &OpcUa_WriteResponse_EncodeableType) {
        OpcUa_WriteResponse* writeResp = reinterpret_cast<OpcUa_WriteResponse*>(response);
        srv.asynchWriteResponse(writeResp);
    } else if (encType == &OpcUa_ReadResponse_EncodeableType) {
        OpcUa_ReadResponse* readResp = reinterpret_cast<OpcUa_ReadResponse*>(response);
        srv.asynchReadResponse(readResp);
    } else {
        WARNING("Unknown response from server 0x%p", encType);
    }
}

/**
 * This function is called to check for user credentials.
 * @param authn The manager context (which contains reference to the server)
 * @param token The authorization token received.
 * @param authenticated The authentication result. Set to SOPC_USER_AUTHENTICATION_REJECTED_TOKEN
 *          or SOPC_USER_AUTHENTICATION_OK
 * @return SOPC_STATUS_OK
 */
static SOPC_ReturnStatus authentication_check(SOPC_UserAuthentication_Manager* authn,
                                              const SOPC_ExtensionObject* token,
                                              SOPC_UserAuthentication_Status* authenticated) {
    assert(nullptr != token && nullptr != authenticated && nullptr != authn);
    const s2opc_north::OPCUA_Server& server = *reinterpret_cast<const s2opc_north::OPCUA_Server*>(authn->pData);

    const SOPC_tools::StringMap_t& users(server.mProtocol.users);

    *authenticated = SOPC_USER_AUTHENTICATION_REJECTED_TOKEN;
    assert(SOPC_ExtObjBodyEncoding_Object == token->Encoding);

    if (&OpcUa_UserNameIdentityToken_EncodeableType == token->Body.Object.ObjType) {
        OpcUa_UserNameIdentityToken* userToken =
                reinterpret_cast<OpcUa_UserNameIdentityToken*>(token->Body.Object.Value);

        const char* username = SOPC_String_GetRawCString(&userToken->UserName);
        SOPC_ByteString* pwd = &userToken->Password;

        for (SOPC_tools::StringPair_t pair : users) {
            if (pair.first == username) {
                // check password
                if (pwd->Length == pair.second.length() &&
                        memcmp(pwd->Data, pair.second.c_str(), pwd->Length) == 0) {
                    *authenticated = SOPC_USER_AUTHENTICATION_OK;
                }
            }
        }
        if (*authenticated == SOPC_USER_AUTHENTICATION_OK) {
            INFO("User '%s' is connecting with correct password", LOGGABLE(username));
        } else {
            WARNING("Failed authentication for user '%s'", LOGGABLE(username));
        }
    }

    return SOPC_STATUS_OK;
}

/** Configuration of callbacks for authentication */
static const SOPC_UserAuthentication_Functions authentication_functions = {
    .pFuncFree = reinterpret_cast<SOPC_UserAuthentication_Free_Func*>(&SOPC_Free),
    .pFuncValidateUserIdentity = &authentication_check};

/**************************************************************************/
/**
 * Callback for write-event on the server
 */
static void C_serverWriteEvent(const SOPC_CallContext* callCtxPtr,
        OpcUa_WriteValue* writeValue,
        SOPC_StatusCode writeStatus) {
    s2opc_north::OPCUA_Server* srv(s2opc_north::OPCUA_Server::instance());
    if (srv != nullptr) {
        if (SOPC_STATUS_OK == writeStatus) {
            srv->writeNotificationCallback(callCtxPtr, writeValue);
        } else {
            WARNING("Client write failed on server. returned code 0x%08X", writeStatus);
        }
    }
}

/**************************************************************************/
static void serverStopped_Fct(SOPC_ReturnStatus status) {
    s2opc_north::OPCUA_Server* srv(s2opc_north::OPCUA_Server::instance());
    if (srv != nullptr) {
        WARNING("Server stopped!");
        srv->setStopped();
    }
}

/**************************************************************************/
static std::string toString(const SOPC_User* pUser) {
    if (pUser != nullptr && SOPC_User_IsUsername(pUser)) {
        const SOPC_String* str(SOPC_User_GetUsername(pUser));
        if (str) {
            return std::string(SOPC_String_GetRawCString(str));
        }
    }
    return s2opc_north::unknownUserName;
}

/**************************************************************************/
static void sopcDoLog(const char* category, const char* const line) {
    SOPC_UNUSED_ARG(category);
    // The Log formats is:
    // [2022/09/07 13:20:18.787] (Error) ....
    static const size_t datelen(strlen("[YYYY/MM/DD HH:MM:SS.SSS] "));
    static const std::string prefixError("(Error)");
    const size_t len = strlen(line);

    if (len > datelen + 2) {
        const std::string text(SOPC_tools::loggableString(line + datelen));
        switch (text[1]) {
        case 'E':
            ERROR("[S2OPC] %s", text.c_str());
            break;
        case 'W':
            WARNING("[S2OPC] %s", text.c_str());
            break;
        case 'D':
            DEBUG("[S2OPC] %s", text.c_str());
            break;
        default:
            INFO("[S2OPC] %s", text.c_str());
            break;
        }
    }
}

}   // extern C

namespace {

/**************************************************************************/
static uint64_t toInteger(const DatapointValue& value) {
    if (value.getType() == DatapointValue::T_INTEGER) {
        return static_cast<uint64_t>(value.toInt());
    } else if (value.getType() == DatapointValue::T_STRING) {
        try {
            return stoll(value.toStringValue(), nullptr, 0);
        }
        catch(const exception &) {
            WARNING("Could not convert STRING %s to an INTEGER value. Using '0'",
                    value.toString().c_str());
        }
        return 0;
    } else {
        WARNING("Could not convert value (not of type 'T_STRING' or 'T_INTEGER')");
        return 0;
    }
}

/**************************************************************************/
static void setupVariant(SOPC_Variant* variant, const DatapointValue* dv, SOPC_BuiltinId typeId) {
    ASSERT_NOT_NULL(variant);
    ASSERT_NOT_NULL(dv);

    const DatapointValue::dataTagType dvType(dv->getType());

    SOPC_Variant_Initialize(variant);
    variant->ArrayType = SOPC_VariantArrayType_SingleValue;
    variant->BuiltInTypeId = typeId;
    variant->DoNotClear = false;
    const bool dvIsStr(dvType == DatapointValue::T_STRING);
    const bool dvIsFloat(dvType == DatapointValue::T_FLOAT);

    bool valid = false;
    // Note: currently unused types are commented to avoid coverage leaks
    switch (typeId) {
    case SOPC_Boolean_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Boolean = static_cast<bool>(dv->toInt());
        }
        break;
//    case SOPC_SByte_Id:
//        if (dvType == DatapointValue::T_INTEGER) {
//            valid = true;
//            variant->Value.Sbyte = static_cast<SOPC_SByte>(dv->toInt());
//        }
//        break;
    case SOPC_Byte_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Byte = static_cast<SOPC_Byte>(dv->toInt());
        }
        break;
//    case SOPC_Int16_Id:
//        if (dvType == DatapointValue::T_INTEGER) {
//            valid = true;
//            variant->Value.Int16 = static_cast<int16_t>(dv->toInt());
//        }
//        break;
//    case SOPC_UInt16_Id:
//        if (dvType == DatapointValue::T_INTEGER) {
//            valid = true;
//            variant->Value.Uint16 = static_cast<uint16_t>(dv->toInt());
//        }
//        break;
    case SOPC_Int32_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Int32 = static_cast<int32_t>(dv->toInt());
        }
        break;
//    case SOPC_UInt32_Id:
//        if (dvType == DatapointValue::T_INTEGER) {
//            valid = true;
//            variant->Value.Uint32 = static_cast<uint32_t>(dv->toInt());
//        }
//        break;
//    case SOPC_Int64_Id:
//        if (dvType == DatapointValue::T_INTEGER) {
//            valid = true;
//            variant->Value.Int64 = static_cast<int64_t>(dv->toInt());
//        }
//        break;
//    case SOPC_UInt64_Id:
//        if (dvType == DatapointValue::T_INTEGER) {
//            valid = true;
//            variant->Value.Uint64 = static_cast<uint64_t>(dv->toInt());
//        }
//        break;
    case SOPC_Float_Id:
        if (dvIsFloat) {
            valid = true;
            variant->Value.Floatv = static_cast<float>(dv->toDouble());
        } else if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Floatv = static_cast<float>(dv->toInt());
        }
        break;
//    case SOPC_Double_Id:
//        if (dvIsFloat) {
//            valid = true;
//            variant->Value.Floatv = static_cast<double>(dv->toDouble());
//        } else if (dvType == DatapointValue::T_INTEGER) {
//        valid = true;
//        variant->Value.Floatv = static_cast<double>(dv->toInt());
//    }
//        break;
//    case SOPC_ByteString_Id:
//        if (dvType == DatapointValue::T_STRING) {
//            valid = true;
//            SOPC_String_InitializeFromCString(&variant->Value.Bstring, dv->toStringValue().c_str());
//        }
//        break;
    case SOPC_String_Id:
        if (dvType == DatapointValue::T_STRING) {
            valid = true;
            SOPC_String_InitializeFromCString(&variant->Value.String, dv->toStringValue().c_str());
        }
        break;
    default:
        break;
    }

    if (!valid) {
        SOPC_Variant_Clear(variant);
        ERROR("Impossible to convert datapoint value (%s) to SOPC type (%d)",
                dv->getTypeStr().c_str() , typeId);
    }
}   // setupVariant()

/**
 * Allocates and return a char* representing the value of a variant.
 */
static string variantToString(const SOPC_Variant& variant) {
    string result;
    // Note: currently unused types are commented to avoid coverage leaks
    switch (variant.BuiltInTypeId) {
    case SOPC_Boolean_Id:
        result = to_string(variant.Value.Boolean);
        break;
//    case SOPC_SByte_Id:
//        result = to_string(variant.Value.Sbyte);
//        break;
    case SOPC_Byte_Id:
        result = to_string(variant.Value.Byte);
        break;
//    case SOPC_Int16_Id:
//        result = to_string(variant.Value.Int16);
//        break;
//    case SOPC_UInt16_Id:
//        result = to_string(variant.Value.Uint16);
//        break;
    case SOPC_Int32_Id:
        result = to_string(variant.Value.Int32);
        break;
//    case SOPC_UInt32_Id:
//        result = to_string(variant.Value.Uint32);
//        break;
//    case SOPC_Int64_Id:
//        result = to_string(variant.Value.Int64);
//        break;
//    case SOPC_UInt64_Id:
//        result = to_string(variant.Value.Uint64);
//        break;
    case SOPC_Float_Id:
        result = to_string(variant.Value.Floatv);
        break;
//    case SOPC_Double_Id:
//        result = to_string(variant.Value.Doublev);
//        break;
//    case SOPC_ByteString_Id:
//        result = SOPC_String_GetRawCString(&variant.Value.Bstring);
//        break;
    case SOPC_String_Id:
        result = SOPC_String_GetRawCString(&variant.Value.String);
        break;
    default:
        WARNING("Could not convert data type %d (Unsupported OPCUA type)", variant.BuiltInTypeId);
        result = "???";
        break;
    }
    return strdup(result.c_str());
}
}   // namespace

using SOPC_tools::loggableString;
namespace SOPC_tools {

/**************************************************************************/
void
CStringVect::
checkAllFilesExist(void)const {
    char*const *p = vect;
    bool result(true);
    while (*p) {
        if (access(*p, R_OK)) {
            FATAL("File not found '%s'", LOGGABLE(*p));
            result = false;
        }
        p++;
    }
    ASSERT(result);
}

}   // namespace SOPC_tools

/**************************************************************************/
namespace {
}   // namespace

/**************************************************************************/
namespace s2opc_north {
using SOPC_tools::statusCodeToCString;

/**************************************************************************/
OPCUA_Server* OPCUA_Server::mInstance = nullptr;
/**************************************************************************/
OPCUA_Server::
OPCUA_Server(const ConfigCategory& configData):
    mProtocol(configData.getValue("protocol_stack")),
    mConfig(configData),
    mBuildInfo(SOPC_CommonHelper_GetBuildInfo()),
    mServerOnline(false),
    mStopped(false),
    m_oper(nullptr),
    m_nbMillisecondShutdown(2) {
    SOPC_ReturnStatus status;

    ASSERT(mInstance == nullptr, "OPCUA_Server may not be instanced twice within the same plugin");

    // Configure the server according to mConfig

    //////////////////////////////////
    // Global initialization
    init_sopc_lib_and_logs();
    DEBUG("S2OPC initialization OK");

    //////////////////////////////////
    // Namespaces initialization
    status = SOPC_HelperConfigServer_SetNamespaces(mProtocol.namespacesUri.size,
            mProtocol.namespacesUri.cVect);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetNamespaces returned code %s(%d)",
            statusCodeToCString(status), status);

    const char* localesArray[2] = {mProtocol.localeId.c_str(), nullptr};
    status = SOPC_HelperConfigServer_SetLocaleIds(1, localesArray);
    ASSERT(status == SOPC_STATUS_OK, "SOPC_HelperConfigServer_SetLocaleIds failed");

    //////////////////////////////////
    // Global descriptions initialization
    status = SOPC_HelperConfigServer_SetApplicationDescription(
            mProtocol.appUri.c_str(), mProtocol.productUri.c_str(),
            mProtocol.serverDescription.c_str(), mProtocol.localeId.c_str(),
            OpcUa_ApplicationType_Server);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetApplicationDescription() returned code %s(%d)",
            statusCodeToCString(status), status);

    //////////////////////////////////
    // Create endpoints configuration
    mEpConfig = SOPC_HelperConfigServer_CreateEndpoint(mProtocol.url.c_str(), true);
    ASSERT_NOT_NULL(mEpConfig);

    INFO("Setting up security...");
    mProtocol.setupServerSecurity(mEpConfig);

    //////////////////////////////////
    // Server certificates configuration
    status = SOPC_HelperConfigServer_SetKeyCertPairFromPath(
            mProtocol.serverCertPath.c_str(),
            mProtocol.serverKeyPath.c_str());
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetKeyCertPairFromPath() returned code %s(%d)",
            statusCodeToCString(status), status);

    // Set PKI configuration
    char* lPathsTrustedLinks[] = {nullptr};
    char* lPathsUntrustedRoots[] = {nullptr};
    char* lPathsUntrustedLinks[] = {nullptr};
    char* lPathsIssuedCerts[] = {nullptr};
    SOPC_PKIProvider* pkiProvider = nullptr;

    // Certificates presence is checked beforehand because S2OPC PKI implementation
    // has no ability to log properly the defaults.
    mProtocol.trustedRootCert.checkAllFilesExist();
    mProtocol.trustedIntermCert.checkAllFilesExist();
    mProtocol.untrustedRootCert.checkAllFilesExist();
    mProtocol.untrustedIntermCert.checkAllFilesExist();
    mProtocol.issuedCert.checkAllFilesExist();
    mProtocol.revokedCert.checkAllFilesExist();

    status = SOPC_PKIProviderStack_CreateFromPaths(
            mProtocol.trustedRootCert.vect, mProtocol.trustedIntermCert.vect,
            mProtocol.untrustedRootCert.vect, mProtocol.untrustedIntermCert.vect,
            mProtocol.issuedCert.vect, mProtocol.revokedCert.vect, &pkiProvider);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_PKIProviderStack_CreateFromPaths() returned code %s(%d). "
            "Check that certificates have correct format.",
            statusCodeToCString(status), status);

    status = SOPC_HelperConfigServer_SetPKIprovider(pkiProvider);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetPKIprovider() returned code %s(%d)",
            statusCodeToCString(status), status);

    INFO("Test_Server_Client: Certificates and key loaded");

    //////////////////////////////////
    // Setup AddressSpace
    SOPC_AddressSpace* addSpace = SOPC_AddressSpace_Create(false);
    ASSERT_NOT_NULL(addSpace);

    const NodeVect_t& nodes(mConfig.addrSpace.nodes);
    INFO("Loading AddressSpace (%u nodes)...", nodes.size());
    for (const NodeInfo_t& nodeInfo : nodes) {
        status = SOPC_AddressSpace_Append(addSpace, nodeInfo.first);
        ASSERT(status == SOPC_STATUS_OK);
    }

    status = SOPC_HelperConfigServer_SetAddressSpace(addSpace);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetAddressSpace() returned code %s(%d)",
            statusCodeToCString(status), status);

    SOPC_UserAuthorization_Manager* authorizationManager = SOPC_UserAuthorization_CreateManager_AllowAll();

    //////////////////////////////////
    // User Management configuration
    SOPC_UserAuthentication_Manager* authenticationManager = new SOPC_UserAuthentication_Manager;
    ASSERT(authenticationManager != nullptr && authorizationManager != nullptr);

    memset(authenticationManager, 0, sizeof (*authenticationManager));

    // Store the reference of the server so that authentication callback can
    // proceed to checks towards configuration.
    authenticationManager->pData = reinterpret_cast<void*>(this);

    authenticationManager->pFunctions = &authentication_functions;
    SOPC_HelperConfigServer_SetUserAuthenticationManager(authenticationManager);
    SOPC_HelperConfigServer_SetUserAuthorizationManager(authorizationManager);

    status = SOPC_HelperConfigServer_SetWriteNotifCallback(&C_serverWriteEvent);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetWriteNotifCallback() returned code %s(%d)",
            statusCodeToCString(status), status);

    //////////////////////////////////
    // Set the asynchronous event callback
    status = SOPC_HelperConfigServer_SetLocalServiceAsyncResponse(SOPC_LocalServiceAsyncRespCallback);
    ASSERT(status == SOPC_STATUS_OK,
            "SetLocalServiceAsyncResponse() returned code %s(%d)",
            statusCodeToCString(status), status);

    //////////////////////////////////
    // Start the server
    SOPC_HelperConfigServer_SetShutdownCountdown(0);
    status = SOPC_ServerHelper_StartServer(&serverStopped_Fct);
    ASSERT(status == SOPC_STATUS_OK,
            "StartServer() returned code %s(%d)",
            statusCodeToCString(status), status);

    // Check for server status after some time. (Start is asynchronous)
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT(!mStopped, "Server failed to start.");

    INFO("Started OPC UA server on endpoint %s", LOGGABLE(mProtocol.url));
    mServerOnline = true;
    mInstance = this;
}

/**************************************************************************/
OPCUA_Server::
~OPCUA_Server() {
    stop();
    OPCUA_Server::uninitialize();
}

/**************************************************************************/
void
OPCUA_Server::
uninitialize(void) {
    SOPC_HelperConfigServer_Clear();
    SOPC_CommonHelper_Clear();
    mInstance = nullptr;
}

/**************************************************************************/
void
OPCUA_Server::
stop(void) {
    SOPC_ServerHelper_StopServer();
    int maxWaitMs(m_nbMillisecondShutdown * 2);
    const int loopMs(10);
    do {
        this_thread::sleep_for(chrono::milliseconds(loopMs));
        maxWaitMs -= loopMs;
    } while (!mStopped && maxWaitMs > 0);
    if (maxWaitMs > 0) {
        ERROR("Could not stop OPC UA services!");
    }
}

/**************************************************************************/
void
OPCUA_Server::
writeNotificationCallback(const SOPC_CallContext* callContextPtr,
        OpcUa_WriteValue* writeValue) {
    ASSERT_NOT_NULL(writeValue);
    using SOPC_tools::toString;
    const SOPC_User* pUser = SOPC_CallContext_GetUser(callContextPtr);
    const string nodeName(toString(writeValue->NodeId));
    if (nullptr != pUser) {
        const std::string username(toString(pUser));
        writeEventNotify(username);
        INFO("Client '%s' wrote into node [%s]", LOGGABLE(username), LOGGABLE(nodeName));
    } else {
        writeEventNotify("");
    }

    if (m_oper != nullptr) {
        // Find the nodeId
        const NodeInfo_t* nodeInfo = mConfig.addrSpace.getByNodeId(nodeName);

        // Ignore write events that are unrelated to functional config.
        if (nodeInfo == nullptr) return;
        const string typeName(nodeInfo->second);
        /*
         * params contains:
         * - OPCUA TypeId
         * - NodeId
         * - Quality
         * - AttributeId
         * - Timestamp
         * - Value
         */
        SOPC_tools::CStringVect names({"typeid", "nodeid", "quality", "attribute", "timestamp", "value"});
        vector<string> params;
        params.push_back(typeName);
        params.push_back(nodeName);
        params.push_back(std::to_string(writeValue->Value.Status));
        params.push_back(std::to_string(writeValue->AttributeId));
        params.push_back(std::to_string(writeValue->Value.SourceTimestamp));
        params.push_back(::variantToString(writeValue->Value.Value));

        SOPC_tools::CStringVect cParams(params);
        char* operName(strdup("opcua_operation"));
        DEBUG("Sending OPERATION(\"%s\", {\"%s\": \"%s\", \"%s\": \"%s\", ...}",
                operName,
                names.vect[0], cParams.vect[0],
                names.vect[5], cParams.vect[5]);
        m_oper(operName, names.size, names.vect, cParams.vect, DestinationBroadcast);

        delete operName;
    } else {
        WARNING("Cannot send operation because oper callback was not set");
    }
}

/**************************************************************************/
void
OPCUA_Server::
asynchWriteResponse(const OpcUa_WriteResponse* writeResp) {
    if (writeResp == nullptr) return;

    SOPC_StatusCode status;

    DEBUG("asynchWriteResponse : %u updates", writeResp->NoOfResults);
    for (int32_t i = 0 ; i < writeResp->NoOfResults; i++) {
        status = writeResp->Results[i];
        if (status != 0) {
            WARNING("Internal data update[%d] failed with code 0x%08X", i, status);
        }
    }
}

/**************************************************************************/
void
OPCUA_Server::
sendAsynchRequest(void* request)const {
    if (nullptr != request) {
        SOPC_ReturnStatus status;
        const uintptr_t thisParam(reinterpret_cast<uintptr_t>(this));
        status = SOPC_ServerHelper_LocalServiceAsync(request, thisParam);
        if (status != SOPC_STATUS_OK) {
            WARNING("LocalServiceAsync failed with code  %s(%d)",
                    statusCodeToCString(status), status);
            SOPC_Free(request);
        }
    }
}

/**************************************************************************/
void
OPCUA_Server::
asynchReadResponse(const OpcUa_ReadResponse* readResp) {}


/**************************************************************************/
void
OPCUA_Server::
init_sopc_lib_and_logs(void) {
    /* Configure the server logger: */
    SOPC_Log_Configuration logConfig = SOPC_Common_GetDefaultLogConfiguration();
    if (mConfig.withLogs) {
        logConfig.logLevel = mConfig.logLevel;
        logConfig.logSystem = SOPC_LOG_SYSTEM_USER;
        logConfig.logSysConfig.userSystemLogConfig.doLog = &sopcDoLog;
    } else {
        INFO("S2OPC logger not configured.");
        logConfig.logLevel = SOPC_LOG_LEVEL_ERROR;
        logConfig.logSystem = SOPC_LOG_SYSTEM_NO_LOG;
    }
    SOPC_ReturnStatus status = SOPC_CommonHelper_Initialize(&logConfig);
    ASSERT(status == SOPC_STATUS_OK && "SOPC_CommonHelper_Initialize failed");

    status = SOPC_HelperConfigServer_Initialize();
    ASSERT(status == SOPC_STATUS_OK && "SOPC_HelperConfigServer_Initialize failed");
}

/**************************************************************************/
void
OPCUA_Server::
updateAddressSpace(SOPC_NodeId* nodeId, SOPC_BuiltinId typeId,
        const DatapointValue* dv, SOPC_StatusCode quality, SOPC_DateTime timestamp)const {
    SOPC_ReturnStatus status;

    OpcUa_WriteRequest* request(SOPC_WriteRequest_Create(1));
    ASSERT_NOT_NULL(request);
    ASSERT_NOT_NULL(nodeId);
    DEBUG("updateAddressSpace(%s)", LOGGABLE(SOPC_tools::toString(*nodeId)));

    SOPC_DataValue opcDv;
    SOPC_DataValue_Initialize(&opcDv);
    opcDv.Status = quality;
    opcDv.SourceTimestamp = timestamp;
    setupVariant(&opcDv.Value, dv, typeId);

    status = SOPC_WriteRequest_SetWriteValue(request, 0, nodeId, SOPC_AttributeId_Value,
            nullptr, &opcDv);
    if (status != SOPC_STATUS_OK) {
        WARNING("SetWriteValue failed with code  %s(%d)",
            statusCodeToCString(status), status);
        delete request;
    }

    sendAsynchRequest(request);
}

/**************************************************************************/
uint32_t
OPCUA_Server::
send(const Readings& readings) {
    DEBUG("OPCUA_Server::send(%ld elements)", readings.size());

    if (!mServerOnline) {
        ERROR("Server not connected, cannot send %u readings", readings.size());
        return 0;
    }

    // Loop over all readings
    for (Reading* reading : readings) {
        if (nullptr == reading) {continue;}
        vector<Datapoint*>& dataPoints = reading->getReadingData();
        const string assetName = reading->getAssetName();

        for (Datapoint* dp : dataPoints) {
            // Only process dataPoints which name match "data_object"
            if (dp->getName() != "data_object") {continue;}
            DEBUG("OPCUA_Server::send(assetName=%s(%u), dpName=%s)",
                    assetName.c_str(),  assetName.length(), dp->getName().c_str());

            DatapointValue dpv = dp->getData();
            vector<Datapoint*>* sdp = dpv.getDpVec();

            // Parameters to be read from Datapoint
            SOPC_BuiltinId typeId = SOPC_Null_Id;
            DatapointValue* value = nullptr;
            SOPC_NodeId* nodeId = nullptr;
            SOPC_StatusCode quality = OpcUa_BadWaitingForInitialData;
            uint64_t ts = 0;

            // Read parameters
            for (Datapoint* objDp : *sdp) {
                const string dpName(objDp->getName());
                const DatapointValue& attrVal = objDp->getData();

                // Read relevant attributes
                if (dpName == "do_type") {
                    if (attrVal.getType() == DatapointValue::T_STRING) {
                        typeId = SOPC_tools::toBuiltinId(attrVal.toStringValue());
                    }
                } else if (dpName == "do_nodeid" && nodeId == nullptr) {
                    // A node Id is either a string or a integer (NS0)
                    if (attrVal.getType() == DatapointValue::T_STRING) {
                        nodeId = SOPC_tools::createNodeId(attrVal.toStringValue());
                    } else if (attrVal.getType() == DatapointValue::T_INTEGER) {
                        uint64_t iNode(attrVal.toInt());
                        nodeId = SOPC_tools::createNodeId(string("i=") + std::to_string(iNode));
                    } else {
                        WARNING("do_nodeid ignored because not of type 'T_STRING' or 'T_INTEGER'");
                    }
                } else if (dpName == "do_value" && value == nullptr) {
                    value = new DatapointValue(attrVal);
                } else if (dpName == "do_quality") {
                    quality = static_cast<SOPC_StatusCode>(::toInteger(attrVal));
                } else if (dpName == "do_ts") {
                    ts = ::toInteger(attrVal);
                }
            }

            if (value != nullptr && nodeId != nullptr && typeId != SOPC_Null_Id) {
                updateAddressSpace(nodeId, typeId, value, quality, ts);
            } else {
                WARNING("Skipped sending data because all fields were not provided or valid");
            }
            delete value;
            delete nodeId;
        }
    }
    return readings.size();
}

/**************************************************************************/
void
OPCUA_Server::
setpointCallbacks(north_operation_event_t operation) {
    m_oper = operation;
    return;
}

}   // namespace s2opc_north

