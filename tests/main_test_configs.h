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
#include <string>
#include <setjmp.h>

// Fledge / tools  includes
#include <plugin_api.h>
#include <gtest/gtest.h>

///////////////////////////////
// catch "C" asserts from S2OPC (leading to ABORT signal)
static jmp_buf abort_jump_env;
static void test_abort_handler(int signo)
{
  if (signo == SIGABRT)
  {
    printf("received SIGABRT\n");
    longjmp(abort_jump_env, 1);
  }
}

// Simply call this macro at each entry point where C may lead to failing assertions
// Any assert will cause a GTest assert fail instead of ABORT signal
#define CATCH_C_ASSERTS ASSERT_NE(signal(SIGABRT, test_abort_handler), SIG_ERR)

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
                                 "typeid":"opcua_dpc"\
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
                            }\
                            ]
        }});

#endif /* INCLUDE_FLEDGE_NORTH_S2OPCUA_TESTS_MAIN_CONFIGS_H_ */
