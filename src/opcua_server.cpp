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
#include <map>
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
#include "opc_maps.inc"

/**************************************************************************/
// Reminder: all callbacks/events called from s2opc must be enclosed in
// extern "C" context!
extern "C" {

static void SOPC_LocalServiceAsyncRespCallback(SOPC_EncodeableType* encType, void* response, uintptr_t appContext) {
    if (appContext == 0) return;  // //LCOV_EXCL_LINE

    s2opc_north::OPCUA_Server& srv(*reinterpret_cast<s2opc_north::OPCUA_Server*>(appContext));
    if (encType == &OpcUa_WriteResponse_EncodeableType) {
        OpcUa_WriteResponse* writeResp = reinterpret_cast<OpcUa_WriteResponse*>(response);
        srv.asynchWriteResponse(writeResp);
    }
    if (encType == &OpcUa_ReadResponse_EncodeableType) {
        OpcUa_ReadResponse* readResp = reinterpret_cast<OpcUa_ReadResponse*>(response);
        srv.asynchReadResponse(readResp);
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
    assert(nullptr != token && nullptr != authenticated && nullptr != authn);  // //LCOV_EXCL_LINE
    const s2opc_north::OPCUA_Server& server = *reinterpret_cast<const s2opc_north::OPCUA_Server*>(authn->pData);

    const SOPC_tools::StringMap_t& users(server.mProtocol.users);

    *authenticated = SOPC_USER_AUTHENTICATION_REJECTED_TOKEN;
    assert(SOPC_ExtObjBodyEncoding_Object == token->Encoding);   // //LCOV_EXCL_LINE

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
    if (srv != nullptr) {  // //LCOV_EXCL_LINE
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
    if (srv != nullptr) {  // //LCOV_EXCL_LINE
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
    static const std::string prefixError("(Error)");                    // //LCOV_EXCL_LINE
    const size_t len = strlen(line);

    if (len > datelen + 2) {   // //LCOV_EXCL_LINE (Robustness)
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

static const uint8_t TRIGGER_MASK_TEST     (1u << 0);
static const uint8_t TRIGGER_MASK_SELECT   (1u << 1);

static inline string boolToString(const bool b)
{
	return (b ? "1" : "0");
}

/**
 * Allocates and return a char* representing the value of a variant.
 */
static string variantToString(const SOPC_Variant& variant) {
    string result("?");
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
//    case SOPC_String_Id:
//        result = SOPC_String_GetRawCString(&variant.Value.String);
//        break;
        // //LCOV_EXCL_START
    default:
        WARNING("Could not convert data type %d (Unsupported OPCUA type)", variant.BuiltInTypeId);
        break;
        // //LCOV_EXCL_STOP
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
    ASSERT(result);  // //LCOV_EXCL_LINE
}

}   // namespace SOPC_tools

/**************************************************************************/
namespace {
}   // namespace

/**************************************************************************/
namespace s2opc_north {
using SOPC_tools::statusCodeToCString;


/**************************************************************************/
const OPCUA_Server::Object_Reader::decoder_map_t
OPCUA_Server::Object_Reader::decoder_map = {
        {"do_id", &decodePivotId},
        {"do_type", &decodeType},
        {"do_cot", &decodeCause},
        {"do_confirmation", &decodeConfirmation},
        {"do_source", &decodeSource},
        {"do_comingfrom", &decodeComingFrom},
        {"do_ts", &decodeTs},
        {"do_ts_org", &decodeTmOrg},
        {"do_ts_validity", &decodeTmValidity},
        {"do_quality", &decodeQuality},
        {"do_ts_quality", &decodeTsQuality},
        {"do_value", &decodeValue},
        {"do_value_quality", &decodeValueQuality},
};

/**************************************************************************/
OPCUA_Server::Object_Reader::
Object_Reader(Datapoints* dp, const std::string& objName):
mPivotId(""),
mInputValue(nullptr),
mValueQuality(0),
mTypeId(SOPC_Null_Id) {
    static DatapointValue DV_zero(0l);            // //LCOV_EXCL_LINE
    static DatapointValue DV_process("process");  // //LCOV_EXCL_LINE
    // Set default values
    setDataValue(&mConfirmation, SOPC_Boolean_Id, &DV_zero);
    setDataValue(&mSource, SOPC_String_Id, &DV_process);
    setDataValue(&mQuality, SOPC_UInt32_Id, &DV_zero);
    setDataValue(&mTsQuality, SOPC_UInt32_Id, &DV_zero);
    setDataValue(&mTsValue, SOPC_UInt64_Id, &DV_zero);

    for (Datapoint* objDp : *dp) {
        const string dpName(objDp->getName());

        decoder_map_t::const_iterator it(decoder_map.find(dpName));
        if (it != decoder_map.end()) {
            DEBUG("Decoding field %s.%s", objName.c_str(), dpName.c_str());
            (*it->second)(this, &objDp->getData());
        } else {
            WARNING("Unknown 'data_object' field '%s'", dpName.c_str());
        }
    }

    if (mInputValue != nullptr && mTypeId != SOPC_Null_Id) {
        // Convert value using expected type
        setDataValue(&mValue, mTypeId, mInputValue);
    }
    // Apply quality to value
    if (mValue.get() != nullptr) {
        mValue.get()->Status = mValueQuality;
    }
    // Check validity

    if (mPivotId == "") {mInvalidityDetails += "Missing do_id, ";}
    if (mTypeId == SOPC_Null_Id) {mInvalidityDetails += "Missing do_type, ";}
    if (mCause.get() == nullptr) {mInvalidityDetails += "Missing do_cot, ";}
    if (mComingFrom.get() == nullptr) {mInvalidityDetails += "Missing do_comingfrom, ";}
    if (mTmOrg.get() == nullptr) {mInvalidityDetails += "Missing do_ts_org, ";}
    if (mTmValidity.get() == nullptr) {mInvalidityDetails += "Missing do_ts_validity, ";}
    if (mValue.get() == nullptr) {mInvalidityDetails += "Missing do_value, ";}
    if (!isValid()) {WARNING("Invalid object:%s", mInvalidityDetails.c_str());}
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodePivotId(Object_Reader* pivot, DatapointValue* data) {
    if (data->getType() == DatapointValue::T_STRING) {
        pivot->mPivotId  = data->toStringValue();
    }
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeType(Object_Reader* pivot, DatapointValue* data) {
    if (data->getType() == DatapointValue::T_STRING) {
        pivot->mTypeId  = SOPC_tools::toBuiltinId(data->toStringValue());
    }
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeCause(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mCause, SOPC_UInt32_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeConfirmation(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mConfirmation, SOPC_Boolean_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeSource(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mSource, SOPC_String_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeComingFrom(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mComingFrom, SOPC_String_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeTmOrg(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mTmOrg, SOPC_String_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeTmValidity(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mTmValidity, SOPC_String_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeTs(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mTsValue, SOPC_UInt64_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeQuality(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mQuality, SOPC_UInt32_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeTsQuality(Object_Reader* pivot, DatapointValue* data) {
    setDataValue(&pivot->mTsQuality, SOPC_UInt32_Id, data);
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeValue(Object_Reader* pivot, DatapointValue* data) {
    pivot->mInputValue = data;
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
decodeValueQuality(Object_Reader* pivot, DatapointValue* data) {
    if (data->getType() == DatapointValue::T_INTEGER) {
        pivot->mValueQuality = static_cast<uint32_t>(data->toInt());
    }
}

/**************************************************************************/
void
OPCUA_Server::Object_Reader::
setDataValue(Value_Ptr* value, const SOPC_BuiltinId typeId, DatapointValue* data) {
    // Conversion from DatapointValue to SOPC_DataValue
    SOPC_DataValue* newValue(new SOPC_DataValue);

    SOPC_DataValue_Initialize(newValue);
    SOPC_Variant & variant(newValue->Value);

    const DatapointValue::dataTagType dvType(data->getType());

    SOPC_Variant_Initialize(&variant);
    variant.ArrayType = SOPC_VariantArrayType_SingleValue;
    variant.BuiltInTypeId = typeId;
    variant.DoNotClear = false;
    bool isValid = false;

    switch (typeId) {
    case SOPC_Boolean_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            isValid = true;
            variant.Value.Boolean = static_cast<bool>(data->toInt());
        }
        break;
    case SOPC_Byte_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            isValid = true;
            variant.Value.Byte = static_cast<uint8_t>(data->toInt());
        }
        break;
    case SOPC_Int32_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            isValid = true;
            variant.Value.Int32 = static_cast<int32_t>(data->toInt());
        }
        break;
    case SOPC_UInt32_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            isValid = true;
            variant.Value.Uint32 = static_cast<uint32_t>(data->toInt());
        }
        break;
    case SOPC_UInt64_Id:
        if (dvType == DatapointValue::T_INTEGER) {
            isValid = true;
            variant.Value.Uint64 = static_cast<uint64_t>(data->toInt());
        }
        break;
    case SOPC_Float_Id:
        if (dvType == DatapointValue::T_FLOAT) {
            isValid = true;
            variant.Value.Floatv = static_cast<float>(data->toDouble());
        } else if (dvType == DatapointValue::T_INTEGER) {
            isValid = true;
            variant.Value.Floatv = static_cast<float>(data->toInt());
        }
        break;
    case SOPC_String_Id:
        if (dvType == DatapointValue::T_STRING) {
            isValid = true;
            SOPC_String_InitializeFromCString(&variant.Value.String,
                    data->toStringValue().c_str());
        }
        break;
        // //LCOV_EXCL_START
    default:
        break;
        // //LCOV_EXCL_STOP
    }
    if (isValid) {
        if (nullptr != value->get()) {
            SOPC_Variant_Clear(&value->get()->Value);
            SOPC_DataValue_Clear(value->get());
        }
        value->reset(newValue);
    } else {
        SOPC_Variant_Clear(&variant);
        SOPC_DataValue_Clear(newValue);
        ERROR("Impossible to convert datapoint value (%s) to SOPC type (%d)",
                data->getTypeStr().c_str() , typeId);
        delete newValue;
    }
}

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

    ASSERT(mInstance == nullptr, "OPCUA_Server may not be instanced twice within the same plugin");  // //LCOV_EXCL_LINE

    // Configure the server according to mConfig

    //////////////////////////////////
    // Global initialization
    init_sopc_lib_and_logs();
    DEBUG("S2OPC initialization OK");

    //////////////////////////////////
    // Namespaces initialization
    status = SOPC_HelperConfigServer_SetNamespaces(mProtocol.namespacesUri.size,
            mProtocol.namespacesUri.cVect);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "SOPC_HelperConfigServer_SetNamespaces returned code %s(%d)",
            statusCodeToCString(status), status);

    const char* localesArray[2] = {mProtocol.localeId.c_str(), nullptr};
    status = SOPC_HelperConfigServer_SetLocaleIds(1, localesArray);
    ASSERT(status == SOPC_STATUS_OK, "SOPC_HelperConfigServer_SetLocaleIds failed");  // //LCOV_EXCL_LINE

    //////////////////////////////////
    // Global descriptions initialization
    status = SOPC_HelperConfigServer_SetApplicationDescription(
            mProtocol.appUri.c_str(), mProtocol.productUri.c_str(),
            mProtocol.serverDescription.c_str(), mProtocol.localeId.c_str(),
            OpcUa_ApplicationType_Server);
    ASSERT(status == SOPC_STATUS_OK,             // //LCOV_EXCL_LINE
            "SOPC_HelperConfigServer_SetApplicationDescription() returned code %s(%d)",
            statusCodeToCString(status), status);

    //////////////////////////////////
    // Create endpoints configuration
    mEpConfig = SOPC_HelperConfigServer_CreateEndpoint(mProtocol.url.c_str(), true);
    ASSERT_NOT_NULL(mEpConfig);  // //LCOV_EXCL_LINE

    INFO("Setting up security...");
    mProtocol.setupServerSecurity(mEpConfig);

    //////////////////////////////////
    // Server certificates configuration
    status = SOPC_HelperConfigServer_SetKeyCertPairFromPath(
            mProtocol.serverCertPath.c_str(),
            mProtocol.serverKeyPath.c_str(),
            false);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
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
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "SOPC_PKIProviderStack_CreateFromPaths() returned code %s(%d). "
            "Check that certificates have correct format.",
            statusCodeToCString(status), status);

    status = SOPC_HelperConfigServer_SetPKIprovider(pkiProvider);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "SOPC_HelperConfigServer_SetPKIprovider() returned code %s(%d)",
            statusCodeToCString(status), status);

    INFO("Test_Server_Client: Certificates and key loaded");

    //////////////////////////////////
    // Setup AddressSpace
    SOPC_AddressSpace* addSpace = SOPC_AddressSpace_Create(false);
    ASSERT_NOT_NULL(addSpace);  // //LCOV_EXCL_LINE

    const NodeVect_t& nodes(mConfig.addrSpace.getNodes());
    INFO("Loading AddressSpace (%u nodes)...", nodes.size());
    for (const NodeInfo_t& nodeInfo : nodes) {
        status = SOPC_AddressSpace_Append(addSpace, nodeInfo.mNode);
        ASSERT(status == SOPC_STATUS_OK);  // //LCOV_EXCL_LINE
    }

    status = SOPC_HelperConfigServer_SetAddressSpace(addSpace);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "SOPC_HelperConfigServer_SetAddressSpace() returned code %s(%d)",
            statusCodeToCString(status), status);

    SOPC_UserAuthorization_Manager* authorizationManager = SOPC_UserAuthorization_CreateManager_AllowAll();

    //////////////////////////////////
    // User Management configuration
    SOPC_UserAuthentication_Manager* authenticationManager = new SOPC_UserAuthentication_Manager;
    ASSERT(authenticationManager != nullptr && authorizationManager != nullptr);   // //LCOV_EXCL_LINE

    memset(authenticationManager, 0, sizeof (*authenticationManager));

    // Store the reference of the server so that authentication callback can
    // proceed to checks towards configuration.
    authenticationManager->pData = reinterpret_cast<void*>(this);

    authenticationManager->pFunctions = &authentication_functions;
    SOPC_HelperConfigServer_SetUserAuthenticationManager(authenticationManager);
    SOPC_HelperConfigServer_SetUserAuthorizationManager(authorizationManager);

    status = SOPC_HelperConfigServer_SetWriteNotifCallback(&C_serverWriteEvent);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "SOPC_HelperConfigServer_SetWriteNotifCallback() returned code %s(%d)",
            statusCodeToCString(status), status);

    //////////////////////////////////
    // Set the asynchronous event callback
    status = SOPC_HelperConfigServer_SetLocalServiceAsyncResponse(SOPC_LocalServiceAsyncRespCallback);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "SetLocalServiceAsyncResponse() returned code %s(%d)",
            statusCodeToCString(status), status);

    //////////////////////////////////
    // Start the server
    SOPC_HelperConfigServer_SetShutdownCountdown(0);
    status = SOPC_ServerHelper_StartServer(&serverStopped_Fct);
    ASSERT(status == SOPC_STATUS_OK,  // //LCOV_EXCL_LINE
            "StartServer() returned code %s(%d)",
            statusCodeToCString(status), status);

    // Check for server status after some time. (Start is asynchronous)
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT(!mStopped, "Server failed to start.");  // //LCOV_EXCL_LINE

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
    ASSERT_NOT_NULL(writeValue);    // //LCOV_EXCL_LINE
    using SOPC_tools::toString;
    const SOPC_User* pUser = SOPC_CallContext_GetUser(callContextPtr);
    const string nodeName(toString(writeValue->NodeId));
    if (nullptr != pUser) {
        const std::string username(toString(pUser));
        writeEventNotify(username);
        INFO("Client '%s' wrote into node [%s]", LOGGABLE(username), LOGGABLE(nodeName));
    } else {
        writeEventNotify("");  // //LCOV_EXCL_LINE
    }

    if (m_oper != nullptr) {
    	const Server_AddrSpace& as(mConfig.addrSpace);
        // Find the nodeId
        const NodeInfo_t* nodeInfo = as.getByNodeId(nodeName);

        // Ignore write events that are unrelated to functional config.
        if (nodeInfo == nullptr)
        {
            WARNING("NodeId [%s] is not supposed to be written (no related event)", LOGGABLE(nodeName));     // //LCOV_EXCL_LINE
        	return;
        }

        const NodeInfoCtx_t& context(nodeInfo->mContext);
        const ControlInfo* ctrlInfo(as.getControlByPivotId(context.mPivotId));
        DEBUG("Found ControlInfo with PivotId='%s', OpcAddress='%s', PivotType='%s', event_type=%d",
        		LOGGABLE(context.mPivotId),
        		LOGGABLE(context.mOpcAddress),
        		LOGGABLE(context.mPivotType),
				context.mEvent);
        if (nullptr == ctrlInfo) {
            WARNING("Missing ControlInfo for PIVOT ID[%s] ", LOGGABLE(context.mPivotId));     // //LCOV_EXCL_LINE
        	return;
        }

        if (context.mEvent == we_Value) {
        	ctrlInfo->mStrValue = ::variantToString(writeValue->Value.Value);
            INFO("Updated co_value for CONTROL PIVOT ID[%s] to '%s' ",
            		LOGGABLE(context.mPivotId), LOGGABLE(ctrlInfo->mStrValue));     // //LCOV_EXCL_LINE
        } else if (context.mEvent == we_Trigger) {
        	// First extract value to resolve trigger mask. Value is expected to be a "Byte"
        	if (!(writeValue->Value.Value.BuiltInTypeId == SOPC_Byte_Id) &&
        			writeValue->Value.Value.ArrayType == SOPC_VariantArrayType_SingleValue)
        	{
                WARNING("TRIGGER for PIVOT ID[%s] does not have the expected OPC type (found type %d)",
                		LOGGABLE(context.mPivotId), writeValue->Value.Value.BuiltInTypeId);     // //LCOV_EXCL_LINE
            	return;
        	}
        	const uint8_t mask(writeValue->Value.Value.Value.Byte);

            static const SOPC_tools::CStringVect names({"co_id", "co_type", "co_value", "co_test", "co_se", "co_ts"});
            vector<string> params;

            // co_id (string) The Pivot Id
            params.push_back(context.mPivotId);
            // co_type (string)
            params.push_back(context.mPivotType);
            // co_value (dynamic type)
            params.push_back(ctrlInfo->mStrValue);
            // co_test (bool)
            params.push_back(boolToString(mask & TRIGGER_MASK_TEST));
            // co_se (bool)
            params.push_back(boolToString(mask & TRIGGER_MASK_SELECT));
            // co_ts (int)
            const time_t seconds = time(NULL);
            params.push_back(to_string(seconds));

            SOPC_tools::CStringVect cParams(params);
            char* operName(strdup("opcua_operation"));
            m_oper(operName, names.size, names.vect, cParams.vect, DestinationBroadcast, nullptr);

            delete operName;
        }
    } else {
        WARNING("Cannot send operation because oper callback was not set");     // //LCOV_EXCL_LINE
    }
}

/**************************************************************************/
void
OPCUA_Server::
asynchWriteResponse(const OpcUa_WriteResponse* writeResp) {
    if (writeResp == nullptr) return;   // //LCOV_EXCL_LINE

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
        // //LCOV_EXCL_START
        if (status != SOPC_STATUS_OK) {
            WARNING("LocalServiceAsync failed with code  %s(%d)",
                    statusCodeToCString(status), status);
            SOPC_Free(request);
        }
        // //LCOV_EXCL_STOP
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
    ASSERT(status == SOPC_STATUS_OK && "SOPC_CommonHelper_Initialize failed");  // //LCOV_EXCL_LINE

    status = SOPC_HelperConfigServer_Initialize();
    ASSERT(status == SOPC_STATUS_OK && "SOPC_HelperConfigServer_Initialize failed");  // //LCOV_EXCL_LINE
}

/**************************************************************************/
class AddressSpace_Item {
 public:
    AddressSpace_Item(const string& nodeId, SOPC_DataValue* dv):
        mNodeId(SOPC_tools::createNodeId(nodeId)),
        mDataValue(dv) {}

    AddressSpace_Item(const AddressSpace_Item&) = delete;
    AddressSpace_Item(const AddressSpace_Item&&) = delete;
    AddressSpace_Item(AddressSpace_Item&&) = delete;
    virtual ~AddressSpace_Item(void) {
        SOPC_NodeId_Clear(mNodeId.get());
    }

    inline SOPC_NodeId* nodeId(void)const {return mNodeId.get();}
    inline SOPC_DataValue* dataValue(void) {return mDataValue;}

 private:
    std::unique_ptr<SOPC_NodeId> mNodeId;
    SOPC_DataValue* mDataValue;
};

/**************************************************************************/
void
OPCUA_Server::
updateAddressSpace(const Object_Reader& object)const {
    using Item_Vector = vector<AddressSpace_Item*>;
    SOPC_ReturnStatus status;

    INFO("updateAddressSpace for PIVOT(%s)", object.pivotId().c_str());

    static const string nodePrefix("ns=1;s=");   // //LCOV_EXCL_LINE
    const string nodePath(nodePrefix + mConfig.addrSpace.getByPivotId(object.pivotId()));
    INFO("updateAddressSpace: address = %s", nodePath.c_str());
    bool failed(false);

    Item_Vector vector;

    vector.emplace_back(new AddressSpace_Item(nodePath + "/Cause", object.cause()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/Source", object.source()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/Confirmation", object.confirmation()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/ComingFrom", object.comingFrom()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/TmOrg", object.tmOrg()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/TmValidity", object.tmValidity()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/DetailQuality", object.quality()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/TimeQuality", object.tsQuality()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/SecondSinceEpoch", object.tsValue()));
    vector.emplace_back(new AddressSpace_Item(nodePath + "/Value", object.value()));

    OpcUa_WriteRequest* request(SOPC_WriteRequest_Create(vector.size()));
    ASSERT_NOT_NULL(request);  // //LCOV_EXCL_LINE

    size_t idx(0);
    for (AddressSpace_Item* item : vector) {
        DEBUG("WriteRequest[%d] = %s", idx, SOPC_tools::toString(*item->nodeId()).c_str());
        status = SOPC_WriteRequest_SetWriteValue(request, idx, item->nodeId(), SOPC_AttributeId_Value,
                    nullptr, item->dataValue());
        // //LCOV_EXCL_START
        if (status != SOPC_STATUS_OK) {
            WARNING("SetWriteValue failed for %s with code  %s(%d)",
                    SOPC_tools::toString(*item->nodeId()).c_str(),
                    statusCodeToCString(status), status);
            failed = true;
        }
        // //LCOV_EXCL_STOP
        idx++;
    }

    if (failed) {
        delete request;  // //LCOV_EXCL_LINE
    } else {
        DEBUG("sendAsynchRequest (%d updates)", vector.size());
        sendAsynchRequest(request);
    }

    for (AddressSpace_Item* item : vector) {
        delete item;  // //LCOV_EXCL_LINE
    }
}

/**************************************************************************/
uint32_t
OPCUA_Server::
send(const Readings& readings) {
    DEBUG("OPCUA_Server::send(%ld elements)", readings.size());

    // //LCOV_EXCL_START
    if (!mServerOnline) {
        ERROR("Server not connected, cannot send %u readings", readings.size());
        return 0;
    }
    // //LCOV_EXCL_STOP

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

            DatapointValue& dpv = dp->getData();
            if (dpv.getType() == DatapointValue::T_DP_DICT) {
                Object_Reader object(dpv.getDpVec(), assetName);
                if (object.isValid()) {
                    updateAddressSpace(object);
                } else {
                    WARNING("Invalid/Incomplete 'data_object' asset name= '%s'", assetName.c_str());
                }
            }
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

