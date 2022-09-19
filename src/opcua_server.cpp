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
#include "s2opc/common/sopc_assert.h"
#include "s2opc/common/sopc_atomic.h"
#include "s2opc/common/sopc_common.h"
#include "s2opc/common/sopc_macros.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/sopc_encodeabletype.h"
#include "s2opc/common/opcua_statuscodes.h"
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/common/sopc_pki.h"
#include "s2opc/common/sopc_pki_stack.h"
#include "s2opc/common/sopc_logger.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/common/sopc_mem_alloc.h"
#include "s2opc/clientserver/frontend/libs2opc_common_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config_custom.h"
#include "s2opc/clientserver/frontend/libs2opc_request_builder.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#include "s2opc/clientserver/sopc_user_manager.h"
#include "s2opc/clientserver/embedded/sopc_addspace_loader.h"
#include "s2opc/clientserver/sopc_toolkit_async_api.h"
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
    assert(NULL != token && NULL != authenticated && NULL != authn);
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
    s2opc_north::OPCUA_Server* srv(s2opc_north::OPCUA_Server::mInstance);
    if (srv != NULL) {
        if (SOPC_STATUS_OK == writeStatus) {
            srv->writeNotificationCallback(callCtxPtr, writeValue);
        } else {
            WARNING("Client write failed on server. returned code 0x%08X", writeStatus);
        }
    }
}

/**************************************************************************/
static void serverStopped_Fct(SOPC_ReturnStatus status) {
    s2opc_north::OPCUA_Server* srv(s2opc_north::OPCUA_Server::mInstance);
    if (srv != NULL) {
        WARNING("Server stopped!");
        srv->setStopped();
    } else {
        ASSERT(false, "Server stopped with return code %s(%d).",
                SOPC_tools::statusCodeToCString(status), status);
    }
#warning "TODO : how can the plugin be stopped properly?"
}

/**************************************************************************/
static std::string toString(const SOPC_User* pUser) {
    if (pUser != NULL && SOPC_User_IsUsername(pUser)) {
        const SOPC_String* str(SOPC_User_GetUsername(pUser));
        if (str) {
            return std::string(SOPC_String_GetRawCString(str));
        }
    }
    return "No username";
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
        case 'I':
            INFO("[S2OPC] %s", text.c_str());
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
    switch (typeId) {
    case SOPC_Boolean_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Boolean = static_cast<bool>(dv->toInt());
        }
        break;
    case SOPC_SByte_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Sbyte = static_cast<SOPC_SByte>(dv->toInt());
        }
        break;
    case SOPC_Byte_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Byte = static_cast<SOPC_Byte>(dv->toInt());
        }
        break;
    case SOPC_Int16_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Int16 = static_cast<int16_t>(dv->toInt());
        }
        break;
    case SOPC_UInt16_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Uint16 = static_cast<uint16_t>(dv->toInt());
        }
        break;
    case SOPC_Int32_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Int32 = static_cast<int32_t>(dv->toInt());
        }
        break;
    case SOPC_UInt32_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Uint32 = static_cast<uint32_t>(dv->toInt());
        }
        break;
    case SOPC_Int64_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Int64 = static_cast<int64_t>(dv->toInt());
        }
        break;
    case SOPC_UInt64_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            valid = true;
            variant->Value.Uint64 = static_cast<uint64_t>(dv->toInt());
        }
        break;
    case SOPC_Float_Id:
        if (dvType == DatapointValue::T_FLOAT) {
            valid = true;
            variant->Value.Floatv = static_cast<float>(dv->toDouble());
        }
        break;
    case SOPC_Double_Id:
        if (dvType == DatapointValue::T_FLOAT) {
            valid = true;
            variant->Value.Floatv = static_cast<double>(dv->toDouble());
        }
        break;
    case SOPC_ByteString_Id:
        if (dvType == DatapointValue::T_STRING) {
            valid = true;
            SOPC_String_InitializeFromCString(&variant->Value.Bstring, dv->toStringValue().c_str());
        }
        break;
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
    SOPC_ASSERT(result);
}

}   // namespace SOPC_tools

/**************************************************************************/
namespace {
}   // namespace

/**************************************************************************/
namespace s2opc_north {
using SOPC_tools::statusCodeToCString;

/**************************************************************************/
OPCUA_Server* OPCUA_Server::mInstance = NULL;
/**************************************************************************/
OPCUA_Server::
OPCUA_Server(const ConfigCategory& configData):
    mProtocol(configData.getValue("protocol_stack")),
    mConfig(configData),
    mBuildInfo(SOPC_CommonHelper_GetBuildInfo()),
    mServerOnline(false),
    mStopped(false) {
    SOPC_ReturnStatus status;

    ASSERT(mInstance == NULL, "OPCUA_Server may not be instanced twice within the same plugin");
    mInstance = this;

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

    const char* localesArray[2] = {mProtocol.localeId.c_str(), NULL};
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
    char* lPathsTrustedLinks[] = {NULL};
    char* lPathsUntrustedRoots[] = {NULL};
    char* lPathsUntrustedLinks[] = {NULL};
    char* lPathsIssuedCerts[] = {NULL};
    SOPC_PKIProvider* pkiProvider = NULL;

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
    SOPC_AddressSpace* addSpace = SOPC_AddressSpace_Create(true);
    ASSERT_NOT_NULL(addSpace);

    const NodeVect_t& nodes(mConfig.addrSpace.nodes);
    INFO("Loading AddressSpace (%u nodes)...", nodes.size());
    for (SOPC_AddressSpace_Node* node : nodes) {
        status = SOPC_AddressSpace_Append(addSpace, node);
        SOPC_ASSERT(status == SOPC_STATUS_OK);
    }

    status = SOPC_HelperConfigServer_SetAddressSpace(addSpace);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetAddressSpace() returned code %s(%d)",
            statusCodeToCString(status), status);

    SOPC_UserAuthorization_Manager* authorizationManager = SOPC_UserAuthorization_CreateManager_AllowAll();

    //////////////////////////////////
    // User Management configuration
    SOPC_UserAuthentication_Manager* authenticationManager = new SOPC_UserAuthentication_Manager;
    SOPC_ASSERT(authenticationManager != NULL && authorizationManager != NULL);

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
    status = SOPC_ServerHelper_StartServer(&serverStopped_Fct);
    ASSERT(status == SOPC_STATUS_OK,
            "StartServer() returned code %s(%d)",
            statusCodeToCString(status), status);

    // Check for server status after some time. (Start is asynchronous)
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT(!mStopped, "Server failed to start.");

    INFO("Started OPC UA server on endpoint %s", LOGGABLE(mProtocol.url));
    mServerOnline = true;
}

/**************************************************************************/
OPCUA_Server::
~OPCUA_Server() {
    SOPC_ServerHelper_StopServer();
    SOPC_HelperConfigServer_Clear();
    SOPC_CommonHelper_Clear();
}

/**************************************************************************/
void
OPCUA_Server::
writeNotificationCallback(const SOPC_CallContext* callContextPtr,
        OpcUa_WriteValue* writeValue) {
    using SOPC_tools::toString;
    const SOPC_User* pUser = SOPC_CallContext_GetUser(callContextPtr);
    const string nodeName(toString(writeValue->NodeId));
    if (NULL != pUser) {
        const std::string username(toString(pUser));
        INFO("Client '%s' wrote into node [%s]", LOGGABLE(username), LOGGABLE(nodeName));
    }
#warning "TODO : manage write events"
}

/**************************************************************************/
void
OPCUA_Server::
asynchWriteResponse(const OpcUa_WriteResponse* writeResp) {
    if (writeResp == NULL) return;

    SOPC_StatusCode status;

    DEBUG("asynchWriteResponse : %u updates", writeResp->NoOfResults);
    for (int32_t i = 0 ; i < writeResp->NoOfResults; i++) {
        status = writeResp->Results[i];
        if (status != 0) {
            WARNING("Internal data update[%d] failed with code 0x%08X", i, status);
        }
    }
#warning "TODO : do we need to manage failures ?"
}

/**************************************************************************/
void
OPCUA_Server::
Server_Event(SOPC_App_Com_Event event, uint32_t idOrStatus, void* param, uintptr_t appContext) {
    (void) idOrStatus;
    if (NULL == mInstance) {
        return;
    }

    SOPC_EncodeableType* message_type = NULL;

    OpcUa_WriteResponse* writeResponse = NULL;

    switch (event) {
    case SE_CLOSED_ENDPOINT:
        INFO("# Info: Closed endpoint event.\n");
        SOPC_Atomic_Int_Set(&mInstance->mServerOnline, 0);
        return;
    case SE_LOCAL_SERVICE_RESPONSE:
        message_type = *(reinterpret_cast<SOPC_EncodeableType**>(param));
        /* Listen for WriteResponses, which only contain status codes */
        /*if (message_type == &OpcUa_WriteResponse_EncodeableType) {
            OpcUa_WriteResponse* write_response = param;
            bool ok = (write_response->ResponseHeader.ServiceResult == SOPC_GoodGenericStatus);
        }*/
        /* Listen for ReadResponses, used in GetSourceVariables
         * This can be used for example when PubSub is defined and uses address space */

        /*if (message_type == &OpcUa_ReadResponse_EncodeableType && NULL != ctx) {
            ctx = (SOPC_PubSheduler_GetVariableRequestContext*) appContext;
            // Then copy content of response to ctx...
        } */
        if (message_type == &OpcUa_WriteResponse_EncodeableType) {
            writeResponse = reinterpret_cast<OpcUa_WriteResponse*>(param);
            // Service should have succeeded
            assert(0 == (SOPC_GoodStatusOppositeMask & writeResponse->ResponseHeader.ServiceResult));
        } else {
            assert(false);
        }
        return;
    default:
        ERROR("# Warning: Unexpected endpoint event: %d.\n", event);
        return;
    }
}

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
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_CommonHelper_Initialize failed");

    status = SOPC_HelperConfigServer_Initialize();
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_HelperConfigServer_Initialize failed");
}

/**************************************************************************/
void
OPCUA_Server::
updateAddressSpace(SOPC_NodeId* nodeId, SOPC_BuiltinId typeId,
        const DatapointValue* dv, SOPC_StatusCode quality, SOPC_DateTime timestamp)const {
    SOPC_ReturnStatus status;
    const uintptr_t thisParam(reinterpret_cast<uintptr_t>(this));

    OpcUa_WriteRequest* request(SOPC_WriteRequest_Create(1));
    ASSERT_NOT_NULL(request);

    SOPC_DataValue opcDv;
    SOPC_DataValue_Initialize(&opcDv);
    opcDv.Status = quality;
    opcDv.SourceTimestamp = timestamp;
    setupVariant(&opcDv.Value, dv, typeId);

    status = SOPC_WriteRequest_SetWriteValue(request, 0, nodeId, SOPC_AttributeId_Value,
            NULL, &opcDv);
    if (status != SOPC_STATUS_OK) {
        WARNING("SetWriteValue failed with code  %s(%d)",
            statusCodeToCString(status), status);
        delete request;
    }

    status = SOPC_ServerHelper_LocalServiceAsync(request, thisParam);
    if (status != SOPC_STATUS_OK) {
        WARNING("LocalServiceAsync failed with code  %s(%d)",
            statusCodeToCString(status), status);
        delete request;
    }
}

/**************************************************************************/
uint32_t
OPCUA_Server::
send(const Readings& readings) {
    DEBUG("OPCUA_Server::send(%ld elements)", readings.size());
    WARNING("OPCUA_Server::send() : NOT IMPLEMENTED YET");

    uint32_t nbSent(0);
    if (!mServerOnline) {
        ERROR("Server not connected, cannot send %u readings", readings.size());
        return 0;
    }

    for (Reading* reading : readings) {
        if (NULL == reading) {continue;}
        vector<Datapoint*>& dataPoints = reading->getReadingData();
        const string assetName = reading->getAssetName();

        for (Datapoint* dp : dataPoints) {
            if (dp->getName() != "data_object") {continue;}

            DatapointValue dpv = dp->getData();
            vector<Datapoint*>* sdp = dpv.getDpVec();

            SOPC_BuiltinId typeId = SOPC_Null_Id;
            DatapointValue* value = nullptr;
            SOPC_NodeId* nodeId = nullptr;
            SOPC_StatusCode quality = OpcUa_BadWaitingForInitialData;
            uint64_t ts = 0;

            for (Datapoint* objDp : *sdp) {
                const string dpName(objDp->getName());
                const DatapointValue& attrVal = objDp->getData();

                if (dpName == "do_type") {
                    typeId = SOPC_tools::toBuiltinId(attrVal.toStringValue());
                } else if (dpName == "do_nodeid" && nodeId == NULL) {
                    nodeId = SOPC_tools::createNodeId(attrVal.toStringValue());
                } else if (dpName == "do_value" && value == NULL) {
                    value = new DatapointValue(attrVal);
                } else if (dpName == "do_quality") {
                    quality = static_cast<SOPC_StatusCode>(attrVal.toInt());
                } else if (dpName == "do_ts") {
                    ts = attrVal.toInt();
                }
#warning 'TODO : Manage TC with "co_type" ...'
            }

            if (value != NULL && nodeId != NULL) {
                updateAddressSpace(nodeId, typeId, value, quality, ts);
                nbSent++;
            }
            delete value;
            delete nodeId;
        }
    }
#warning "TODO : OPCUA_Server::send"
    return nbSent;
}

/**************************************************************************/
void
OPCUA_Server::
setpointCallbacks(north_write_event_t write, north_operation_event_t operation) {
    DEBUG("OPCUA_Server::setpointCallbacks(.., ..)");
    WARNING("OPCUA_Server::setpointCallbacks() : NOT IMPLEMENTED YET");
#warning "TODO : OPCUA_Server::setpointCallbacks"
    return;
}

}   // namespace s2opc_north

