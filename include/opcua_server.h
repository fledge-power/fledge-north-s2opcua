#ifndef INCLUDE_OPCUA_SERVER_H_
#define INCLUDE_OPCUA_SERVER_H_
/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */

// Plugin headers
#include "opcua_server_tools.h"
#include "opcua_server_config.h"

// System headers
#include <stdint.h>
#include <stdlib.h>
#include <atomic>
#include <string>
#include <mutex>
#include <thread>
#include <map>
#include <vector>
#include <memory>

// Fledge headers
#include "config_category.h"
#include "reading.h"
#include "logger.h"
#include "utils.h"
#include "plugin_api.h"

extern "C" {
// S2OPC Headers
#include "sopc_types.h"
#include "sopc_builtintypes.h"
#include "sopc_logger.h"
#include "sopc_user_app_itf.h"
#include "sopc_toolkit_config.h"
};

using Readings = std::vector<Reading*>;
using Datapoints = std::vector<Datapoint *>;

namespace s2opc_north {

/*****************************************************
 *  CONFIGURATION
 *****************************************************/
extern const char* const plugin_default_config;

/*****************************************************
 *  TYPES DEFINITIONS
 *****************************************************/
static const char unknownUserName[] = "-UnknownUserName-";

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
using Item_Vector = vector<AddressSpace_Item*>;

/**
 * Interface to the S2 OPCUA library for a S2OPC server
 */
class OPCUA_Server {
 public:
    /** Create a new OPC server with the given configuration
     * @param configData The configuration of the plugin
     */
    explicit OPCUA_Server(const ConfigCategory& configData);

    /**
     * Destructor
     */
    virtual ~OPCUA_Server(void);

    /**
     * Stops the server and waits for its termination
     */
    void stop(void);

    /**
     * Sends the readings on the OPC server
     * @param readings The objects to update
     * @return The number of element written
     */
    uint32_t send(const Readings& readings);

    /**
     * Register the "operation" callback.
     * This function can be called when a command is received from controller side (opc client)
     * and needs to be sent back to any south plugin.
     */
    void setpointCallbacks(north_operation_event_t operation);

    /**
     * Process a write event on the server
     * \param callContextPtr The write context (including user)
     * \param  writeValue The value written
     */
    void writeNotificationCallback(
            const SOPC_CallContext* callContextPtr,
            OpcUa_WriteValue* writeValue);

    /**
     * Send an asynchronous request to the server.
     * @param request An object created by SOPC_ReadRequest_Create or
     *      SOPC_WriteRequest_Create. It shall not be freed by caller
     */
    void sendAsynchRequest(void* request)const;

    virtual void asynchWriteResponse(const OpcUa_WriteResponse* writeResp);
    virtual void asynchReadResponse(const OpcUa_ReadResponse* readResp);
    void setStopped(void);

    /** Call this method to clean up SOPC libraries in the case
     * the constructor failed (in that case the destructor will not be called,
     * so that calling this clean up will be required to re-instanciate plugin
     */
    static void uninitialize(void);

 protected:
    virtual void writeEventNotify(const std::string& username) {
        // This method intends at providing a child class the ability to
        // monitor events
    }
    inline void setShutdownDuration(const int nbMs) {m_nbMillisecondShutdown = nbMs;}

 private:
    void init_sopc_lib_and_logs(void);

    class Object_Reader {
     public:
        explicit Object_Reader(Datapoints* dp, const std::string& objName);
        virtual ~Object_Reader(void) = default;

        inline bool isValid(void)const {return mInvalidityDetails == "";}
        inline const string& pivotId(void)const {return mPivotId;}
        inline SOPC_DataValue* cause(void)const {return mCause.get();}
        inline SOPC_DataValue* source(void)const {return mSource.get();}
        inline SOPC_DataValue* comingFrom(void)const {return mComingFrom.get();}
        inline SOPC_DataValue* confirmation(void)const {return mConfirmation.get();}
        inline SOPC_DataValue* tmOrg(void)const {return mTmOrg.get();}
        inline SOPC_DataValue* tmValidity(void)const {return mTmValidity.get();}
        inline SOPC_DataValue* quality(void)const {return mQuality.get();}
        inline SOPC_DataValue* tsQuality(void)const {return mTsQuality.get();}
        inline SOPC_DataValue* tsValue(void)const {return mTsValue.get();}
        inline SOPC_DataValue* value(void)const {return mValue.get();}

     private:
        using FieldDecoder = void (*) (Object_Reader*, DatapointValue*);
        using decoder_map_t = std::map<std::string, FieldDecoder>;
        static void decodePivotId(Object_Reader* pivot, DatapointValue* data);
        static void decodeType(Object_Reader* pivot, DatapointValue* data);
        static void decodeCause(Object_Reader* pivot, DatapointValue* data);
        static void decodeConfirmation(Object_Reader* pivot, DatapointValue* data);
        static void decodeSource(Object_Reader* pivot, DatapointValue* data);
        static void decodeComingFrom(Object_Reader* pivot, DatapointValue* data);
        static void decodeTmOrg(Object_Reader* pivot, DatapointValue* data);
        static void decodeTs(Object_Reader* pivot, DatapointValue* data);
        static void decodeTmValidity(Object_Reader* pivot, DatapointValue* data);
        static void decodeQuality(Object_Reader* pivot, DatapointValue* data);
        static void decodeTsQuality(Object_Reader* pivot, DatapointValue* data);
        static void decodeValue(Object_Reader* pivot, DatapointValue* data);
        static void decodeValueQuality(Object_Reader* pivot, DatapointValue* data);

        using Value_Ptr = std::unique_ptr<SOPC_DataValue>;
        static void setDataValue(Value_Ptr* value, const SOPC_BuiltinId typeId, DatapointValue* data);

        static const decoder_map_t decoder_map;
        string mPivotId;                  // do_id
        SOPC_BuiltinId mTypeId;           // do_type
        Value_Ptr mCause;                 // do_cot
        Value_Ptr mConfirmation;          // do_confirmation
        Value_Ptr mSource;                // do_source
        Value_Ptr mComingFrom;            // do_comingfrom
        Value_Ptr mTmOrg;                 // do_ts_org
        Value_Ptr mTmValidity;            // do_ts_validity
        Value_Ptr mQuality;               // do_quality
        Value_Ptr mTsQuality;             // do_ts_quality
        Value_Ptr mTsValue;               // do_ts
        DatapointValue* mInputValue;      // do_value
        Value_Ptr mValue;                 // do_value
        uint32_t  mValueQuality;          // do_value_quality
        string    mInvalidityDetails;
    };  // Object_Reader

    /**
     * This function updates a node Id in the address space given a DatapointValue
     */
    void updateAddressSpace(const Object_Reader& object)const;

    int m_nbMillisecondShutdown;

 public:
    const OpcUa_Protocol mProtocol;
    const OpcUa_Server_Config mConfig;
    const SOPC_Toolkit_Build_Info mBuildInfo;
    static OPCUA_Server* instance(void) {return mInstance;}
    /**
     * Send a write request to the server.
     * @param items A vector of allocated ::AddressSpace_Item.
     * In all cases, the elements in items are freed when the function returns and shall not be reused.
     * @post After write is terminated (success or not), the ::asynchWriteResponse callback is called by the stack.
     */
    void sendWriteRequest(const Item_Vector& items)const;
 private:
    static OPCUA_Server* mInstance;
    std::atomic<bool> mStopped;
    int32_t mServerOnline;
    SOPC_Endpoint_Config* mEpConfig;
    north_operation_event_t m_oper;
};

inline void
OPCUA_Server::
setStopped(void) {
    mStopped = true;
}

}   // namespace s2opc_north

#endif  // INCLUDE_OPCUA_SERVER_H_
