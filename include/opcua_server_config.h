#ifndef _OPCUA_SERVER_CONFIG_H
#define _OPCUA_SERVER_CONFIG_H
/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */
#include <config_category.h>
#include <string>
#include <logger.h>
#include <utils.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

/* HELPER MACROS*/
#define DEBUG Logger::getLogger()->debug
#define INFO Logger::getLogger()->info
#define WARNING Logger::getLogger()->warn
#define ERROR Logger::getLogger()->error
#define FATAL Logger::getLogger()->fatal

// Improve SOPC_ASSERT to allow run-time elaborated messages
#define ASSERT(c,  ...) do \
{\
    if(!(c))\
    {\
        FATAL ("ASSERT FAILED:" __VA_ARGS__);\
        SOPC_ASSERT(false);\
    }\
} while(0)

namespace SOPC_tools
{

/**
 * @param status a S2OPC status code
 * @return a human-readable representation of a status code
 */
extern const char* statusCodeToCString(const int status);

/** Vector of string */
typedef std::vector<std::string> StringVect_t;

/**
 * CStringVect intends at making a String vector useable by C S2OPC layer.
 * @field vect Contains a C-representation of the array, including a
 *  NULL terminating string
 * @field size The number of non-NULL elements in vect
 */
struct CStringVect
{
    /**
     * Build a C vector using  C+ STL vector
     */
    CStringVect(const StringVect_t& ref);
    /** Frees vect */
    virtual ~ CStringVect(void);
    /**
     * \brief Checks (using ASSERT) that all elements in vector are R-O accessible files
     */
    void checkAllFilesExist(void)const;
    size_t size;
    char** vect;
};

typedef std::pair<std::string, std::string> StringPair_t;
typedef std::vector<StringPair_t> StringMap_t;

}

namespace s2opc_north
{
using namespace SOPC_tools;

/**
 * Configuration holder for a S2OPC server.
 * This class intends at interpreting all parameters provided by the configuration
 * and storing them into directly usable items.
 */
class OpcUa_Server_Config
{
public:
    OpcUa_Server_Config(const ConfigCategory& configData);
    virtual ~OpcUa_Server_Config(void);
public:
    /**
     * \brief  set up a \a SOPC_Endpoint_Config object with the  current configuration
     * \param ep The object to initialize
     */
    void setupServerSecurity(SOPC_Endpoint_Config* ep)const;

public:
    // All fields are constants, and thus can be public.
    const std::string url;
    const std::string appUri;
    const std::string productUri;
    const std::string localeId;
    const std::string serverDescription;
    const std::string serverCertPath;
    const std::string serverKeyPath;
    const std::string certificates;
    const SOPC_tools::CStringVect trustedRootCert;
    const SOPC_tools::CStringVect trustedIntermCert;
    const SOPC_tools::CStringVect untrustedRootCert;
    const SOPC_tools::CStringVect untrustedIntermCert;
    const SOPC_tools::CStringVect revokedCert;
    const SOPC_tools::CStringVect issuedCert;
    const bool withLogs;
    const SOPC_Log_Level logLevel; // only relevant if withLogs is true
    const std::string logPath;
    const SOPC_tools::StringVect_t policies;
    const std::string namespacesStr;
    const SOPC_tools::CStringVect namespacesUri;
    const StringMap_t users;
};

}

#endif
