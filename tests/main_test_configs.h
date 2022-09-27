/*
 * Fledge north service plugin (TESTS)
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

#ifndef INCLUDE_FLEDGE_NORTH_S2OPCUA_TESTS_MAIN_CONFIGS_H_
#define INCLUDE_FLEDGE_NORTH_S2OPCUA_TESTS_MAIN_CONFIGS_H_

// System includes
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <fstream>
#include <string>

// Fledge / tools  includes
#include <plugin_api.h>
#include <datapoint.h>
#include <gtest/gtest.h>

extern "C" {
// S2OPC Headers
#include "sopc_assert.h"
}

///////////////////////////////
// catch "C" asserts from S2OPC
extern "C" {

static bool abort_jump_env_set = false;
static jmp_buf abort_jump_env;

static void test_Assert_UserCallback(const char* context) {
    FATAL("ASSERT failed. Context = %s", (context ? context : "[NULL]"));
    if (abort_jump_env_set)
        longjmp(abort_jump_env, 0xDEAD);
    assert(false);
}
}

///////////////////////
// helpful test macros
#define ASSERT_STR_CONTAINS(s1,s2) ASSERT_NE(s1.find(s2), string::npos);
#define ASSERT_STR_NOT_CONTAINS(s1,s2) ASSERT_EQ(s1.find(s2), string::npos);

#define WAIT_UNTIL(c, mtimeoutMs) do {\
        int maxwaitMs(mtimeoutMs);\
        do {\
            this_thread::sleep_for(chrono::milliseconds(10));\
            maxwaitMs -= 10;\
        } while (!(c) && maxwaitMs > 0);\
    } while(0)

// Simply call this macro at each entry point where C may lead to failing assertions
// Any assert will cause a GTest assert fail instead of ABORT signal
#define ASSERT_NO_C_ASSERTION do {\
        SOPC_Assert_Set_UserCallback(&test_Assert_UserCallback);\
        int val = setjmp(abort_jump_env); \
        abort_jump_env_set = true; \
        ASSERT_EQ(val, 0); \
} while(0)

/**
 * Enclose some code with ASSERT_C_RAISES_ASSERTION_xxx to catch and check C failed assertions
 * e.g.
 * f(){
 * ASSERT_C_RAISES_ASSERTION_START;
 * some_code_that_raises_c_assert();
 * ASSERT_C_RAISES_ASSERTION_END;
 * }
 */

#define ASSERT_C_RAISES_ASSERTION_START do {\
        SOPC_Assert_Set_UserCallback(&test_Assert_UserCallback);\
        int valAbortResult = setjmp(abort_jump_env); \
        abort_jump_env_set = true; \
        if (valAbortResult != 0) {\
            ASSERT_EQ(valAbortResult, 0xDEAD);\
            break;\
        }\
        do {} while(0)  // Note: this line just intends at handling the ';' in caller

#define ASSERT_C_RAISES_ASSERTION_END \
        ASSERT_FALSE("No exception raised"); \
} while(0)

//////////////////////////////////////
// TEST HELPER FUNCTIONS

static inline Datapoint* createStringDatapointValue(const std::string& name,
        const std::string& value) {
    DatapointValue dpv(value);
    return new Datapoint(name, dpv);
}

static inline Datapoint* createIntDatapointValue(const std::string& name,
        const long value) {
    DatapointValue dpv(value);
    return new Datapoint(name, dpv);
}

static inline Datapoint* createFloatDatapointValue(const std::string& name,
        const float value) {
    DatapointValue dpv(value);
    return new Datapoint(name, dpv);
}

///////////////////////
// This function starts a process and return the standard output result
static std::string launch_and_check(SOPC_tools::CStringVect& command) {
    sigset_t mask;
    sigset_t orig_mask;
    struct timespec timeout;
    pid_t pid;

    static const char* filename("./fork.log");
    sigemptyset (&mask);
    sigaddset (&mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0) {
        return "sigprocmask";
    }
    timeout.tv_sec = 2;
    timeout.tv_nsec = 0;

    pid = fork();
    if (pid < 0) return "fork";

    if (pid == 0) {
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        dup2(fd, 1);  // redirect stdout
        char **args = command.vect;
        execv(args[0], args);
        throw std::exception(); // not reachable
    }

    do {
        if (sigtimedwait(&mask, NULL, &timeout) < 0) {
            if (errno == EINTR) {
                /* Interrupted by a signal other than SIGCHLD. */
                continue;
            }
            else if (errno == EAGAIN) {
                printf ("Timeout, killing child\n");
                kill (pid, SIGKILL);
            }
            else {
                return "sigtimedwait";
            }
        }

        break;
    } while (1);

    int result = -1;
    waitpid(pid, &result, 0);

    std::ifstream ifs(filename);
    std::string content( (std::istreambuf_iterator<char>(ifs) ),
                           (std::istreambuf_iterator<char>()    ) );

    if (WIFEXITED(result) == 0 || WEXITSTATUS(result) != 0) {
        std::cerr << "While executing command:" << std::endl;
        for (const std::string& sRef : command.cppVect) {
            std::cout << "'" << sRef << "' ";
        }
        std::cerr << std::endl;
        std::cerr << "Log was:<<<" << content << ">>>" << std::endl;
        return command.cppVect[0] + " has terminated with code " +
                std::to_string(WEXITSTATUS(result));
    }

    return content;
}

//////////////////////////////////////
// TEST CONFIGURATIONS
static const std::string protocolJsonOK =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
            "version":"1.0", \
            "transport_layer":{ \
            "url" : "opc.tcp://localhost:55345", \
            "appUri" : "urn:S2OPC:localhost", \
            "productUri" : "urn:S2OPC:localhost", \
            "appDescription": "Application description", \
            "localeId" : "en-US", \
            "namespaces" : [ "urn:S2OPC:localhost" ], \
            "policies" : [ \
                           { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] },\
                           { "securityMode" : "Sign", "securityPolicy" : "Basic256", "userPolicies" : [ "anonymous", "username" ] }, \
                           { "securityMode" : "SignAndEncrypt", "securityPolicy" : "Basic256Sha256", "userPolicies" : \
                               [ "anonymous", "anonymous", "username_Basic256Sha256", "username_None" ] } ], \
                               "users" : {"user" : "password", "user2" : "xGt4sdE3Z+" }, \
                               "certificates" : { \
                                   "serverCertPath" : "server_2k_cert.der", \
                                   "serverKeyPath" : "server_2k_key.pem", \
                                   "trusted_root" : [ "cacert.der" ],  \
                                   "trusted_intermediate" : [ ], \
                                   "revoked" : [ "cacrl.der" ], \
                                   "untrusted_root" : [ ], \
                                   "untrusted_intermediate" : [ ], \
                                   "issued" : [  ] } \
        } \
        } });

static const std::string aSpaceJsonOK = QUOTE( { "exchanged_data" : {\
    "name" : "FESSE_6_FESS5.1_DFAIL.DJ",\
    "version" : "1.0", \
    "datapoints" : [\
                    {\
        "label":"FESSE_6_FESS5.1_DFAIL.DJ",\
        "pivot_id":"S114562128",\
        "pivot_type":"SpsTyp",\
        "protocols":[\
                     {\
            "name":"iec104",\
            "address":"18325-6468171",\
            "typeid":"M_SP_TB_1",\
            "gi_groups":"station"\
                     },\
                     {\
                         "name":"opcua",\
                         "address":"S_1145_6_21_28",\
                         "typeid":"opcua_sps"\
                     }\
                     ]\
                    }\
                    ,\
                    {\
                        "label":"FESSE_6_6CHAL7.1_SA.1",\
                        "pivot_id":"C11456181",\
                        "pivot_type":"DpcTyp",\
                        "protocols":[\
                                     {\
                            "name":"iec104",\
                            "address":"18325-6441925",\
                            "typeid":"C_DC_TA_1"\
                                     },\
                                     {\
                                         "name":"opcua",\
                                         "address":"C_1145_6_18_1",\
                                         "typeid":"opcua_dpc"\
                                     }\
                                     ] \
                    }\
                    ]\
}});

static const std::string config_exData = QUOTE(
        {"exchanged_data" : {
            "name" : "data1",
            "version" : "1.0",
            "datapoints" : [
            {\
               "label" : "label1",
               "pivot_id" : "pivot1",
               "pivot_type": "type1",
               "protocols":[\
                  {\
                   "name":"iec104",\
                   "address":"18325-6441925",\
                   "typeid":"C_DC_TA_1"\
                  },\
                  {\
                    "name":"opcua",\
                    "address":"addr1",\
                    "typeid":"opcua_dps"\
                   }\
                 ]\
               },\
               {\
                  "label" : "labelMVF",
                  "pivot_id" : "pivotMVF",
                  "pivot_type": "typeMVF",
                  "protocols":[\
                     {\
                       "name":"opcua",\
                       "address":"mvf",\
                       "typeid":"opcua_mvf"\
                      }\
                    ]\
                }, \
                {\
                   "label" : "labelMVA",
                   "pivot_id" : "pivotMVA",
                   "pivot_type": "typeMVA",
                   "protocols":[\
                      {\
                        "name":"opcua",\
                        "address":"mva",\
                        "typeid":"opcua_mva"\
                       }\
                     ]\
                   },
                {\
                 "label" : "label2",
                 "pivot_id" : "pivot2",
                 "pivot_type": "type2",
                 "protocols":[\
                   {\
                     "name":"opcua",\
                     "address":"addr2",\
                     "typeid":"opcua_sps"\
                    }\
                   ]\
                 },
                 {\
                  "label" : "labelSPC",
                  "pivot_id" : "pivotSPC",
                  "pivot_type": "typeSPC",
                  "protocols":[\
                    {\
                      "name":"opcua",\
                      "address":"spc",\
                      "typeid":"opcua_spc"\
                     }\
                    ]\
                  },
                  {\
                   "label" : "labelAPC",
                   "pivot_id" : "pivotAPC",
                   "pivot_type": "typeAPC",
                   "protocols":[\
                     {\
                       "name":"opcua",\
                       "address":"apc",\
                       "typeid":"opcua_apc"\
                      }\
                     ]\
                   },
                   {\
                    "label" : "labelINC",
                    "pivot_id" : "pivotINC",
                    "pivot_type": "typeINC",
                    "protocols":[\
                      {\
                        "name":"opcua",\
                        "address":"inc",\
                        "typeid":"opcua_inc"\
                       }\
                      ]\
                    },
                   {\
                    "label" : "labelDPC",
                    "pivot_id" : "pivotDPC",
                    "pivot_type": "typeDPC",
                    "protocols":[\
                      {\
                        "name":"opcua",\
                        "address":"dpc",\
                        "typeid":"opcua_dpc"\
                       }\
                      ]\
                    }
             ]
        }});

static const std::string protocolMissingFile =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
            "version":"1.0", \
            "transport_layer":{ \
            "url" : "opc.tcp://localhost:55345", \
            "appUri" : "urn:S2OPC:localhost", \
            "productUri" : "urn:S2OPC:localhost", \
            "appDescription": "Application description", \
            "localeId" : "en-US", \
            "namespaces" : [ "urn:S2OPC:localhost" ], \
            "policies" : [ \
                           { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] },\
                           { "securityMode" : "Sign", "securityPolicy" : "Basic256", "userPolicies" : [ "anonymous", "username" ] }, \
                           { "securityMode" : "SignAndEncrypt", "securityPolicy" : "Basic256Sha256", "userPolicies" : \
                               [ "anonymous", "anonymous", "username_Basic256Sha256", "username_None" ] } ], \
                               "users" : {"user" : "password", "user2" : "xGt4sdE3Z+" }, \
                               "certificates" : { \
                                   "serverCertPath" : "server_2k_cert.der", \
                                   "serverKeyPath" : "server_2k_key.pem", \
                                   "trusted_root" : [ "cacert.der" ],  \
                                   "trusted_intermediate" : [ ], \
                                   "revoked" : [ "cacrl.der", "missingfile.der" ], \
                                   "untrusted_root" : [ ], \
                                   "untrusted_intermediate" : [ ], \
                                   "issued" : [  ] } \
        } \
        } });

#endif /* INCLUDE_FLEDGE_NORTH_S2OPCUA_TESTS_MAIN_CONFIGS_H_ */
