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
#include <exception>
#include <string>
#include <regex>

// Fledge / tools  includes
#include <plugin_api.h>
#include <datapoint.h>
#include <gtest/gtest.h>

extern "C" {
// S2OPC Headers
#include "sopc_assert.h"
}

// Tested files
#include "opcua_server.h"
#include "opcua_server_tools.h"

using SOPC_tools::StringVect_t;

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


//////////////////////////////////////
// TEST HELPER CLASS
// Complete OPCUA_Server class to test Server updates
class OPCUA_Server_Test : public s2opc_north::OPCUA_Server {
public:
    explicit OPCUA_Server_Test(const ConfigCategory& configData):
        OPCUA_Server(configData),
        nbResponses(0),
        nbBadResponses(0) {
        setShutdownDuration(500);
    }

    virtual ~OPCUA_Server_Test(void) {WARNING("Test Server destroyed");}

    void reset(void) {
        nbResponses = 0;
        nbBadResponses = 0;
        lastWriterName = "";
    }
    size_t nbResponses;
    size_t nbBadResponses;
    string lastWriterName;

    virtual void writeEventNotify(const std::string& username) {
        lastWriterName = username;
    }

    virtual void asynchWriteResponse(const OpcUa_WriteResponse* writeResp) {
        OPCUA_Server::asynchWriteResponse(writeResp);
        if (writeResp == NULL) return;

        SOPC_StatusCode status;

        DEBUG("asynchWriteResponse : %u updates", writeResp->NoOfResults);
        for (int32_t i = 0 ; i < writeResp->NoOfResults; i++) {
            status = writeResp->Results[i];
            if (status != 0) {
                WARNING("Internal data update[%d] failed with code 0x%08X", i, status);
                nbBadResponses++;
            }
            nbResponses++;
        }
    }

    std::vector<string> readResults;
    virtual void asynchReadResponse(const OpcUa_ReadResponse* readResp) {
        OPCUA_Server::asynchReadResponse(readResp);

        SOPC_StatusCode status;
        if (readResp == NULL) return;
        for (int32_t i = 0 ; i < readResp->NoOfResults; i++) {
            const SOPC_DataValue& result(readResp->Results[i]);
            char quality[4 + 8 + 4 +1];
            sprintf(quality, "Q=0x%08X,V=", result.Status);
            DEBUG("asynchReadResponse : type %d, status 0x%08X ", result.Value.BuiltInTypeId,
                    result.Status);
            string value("?");
            if (result.Value.BuiltInTypeId == SOPC_String_Id) {
                value = SOPC_String_GetRawCString(&result.Value.Value.String);
            } else  if (result.Value.BuiltInTypeId == SOPC_Byte_Id) {
                value = std::to_string(result.Value.Value.Byte);
            } else  if (result.Value.BuiltInTypeId == SOPC_Int32_Id) {
                value = std::to_string(result.Value.Value.Int32);
            } else  if (result.Value.BuiltInTypeId == SOPC_Float_Id) {
                value = std::to_string(static_cast<int>(result.Value.Value.Floatv)) +
                        ".(...)";
            } else  if (result.Value.BuiltInTypeId == SOPC_Boolean_Id) {
                value = std::to_string(result.Value.Value.Boolean);
            } else {
                value = string("Unsupported type: typeId=") +
                        std::to_string(result.Value.BuiltInTypeId);
            }

            readResults.push_back(string(quality) + value);
        }
    }
};

//////////////////////////////////////
// TEST HELPER FUNCTIONS
#define replace_in_string(a,b,c) _replace_in_string(a,b,c,__FILE__, __LINE__)
namespace {
std::string _replace_in_string(
        const std::string& ref, const std::string& old, const std::string& New,
        const char* file, const int line) {
    string result = std::regex_replace(ref, std::regex(old), New);
    if(result == ref) {
        printf("Test String unchanged by regex <%s> in %s:%d:\n", old.c_str(), file, line);
        printf("\n=>[TXT]=<%s>\n", ref.c_str());
        printf("\n=>[CHG]=<%s>\n", old.c_str());
        throw std::exception();
    }
    // INFO("Test String changed by regex <%s> in %s:%d: <%s> ", old.c_str(), file, line, ref.c_str());
    return result;
}
}

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
    std::remove(filename);

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

struct nodeVarFinder {
    nodeVarFinder(const std::string& name):m_name(name){}
    bool operator()(const s2opc_north::NodeInfo_t& nodeInfo){
        SOPC_AddressSpace_Node* node = nodeInfo.first;
        return node != NULL &&
                ( (node->node_class == OpcUa_NodeClass_Variable &&
                SOPC_tools::toString(node->data.variable.NodeId) == m_name) ||
                (node->node_class == OpcUa_NodeClass_Object &&
                SOPC_tools::toString(node->data.object.NodeId) == m_name));
    }
    const std::string m_name;
};

inline s2opc_north::NodeVect_t::const_iterator findNodeInASpc(
        const s2opc_north::Server_AddrSpace& spc, const string& node) {
    return std::find_if(spc.getNodes().begin(), spc.getNodes().end(),
            nodeVarFinder(node));
}

struct nodeVarTypeFinder {
    nodeVarTypeFinder(const std::string& name):m_name(name){}
    bool operator()(const s2opc_north::NodeInfo_t& nodeInfo){
        SOPC_AddressSpace_Node* node = nodeInfo.first;
        return node != NULL &&
                node->node_class == OpcUa_NodeClass_VariableType &&
                SOPC_tools::toString(node->data.variable_type.NodeId) == m_name;
    }
    const std::string m_name;
};

struct nodeObjFinder {
    nodeObjFinder(const std::string& name):m_name(name){}
    bool operator()(const s2opc_north::NodeInfo_t& nodeInfo){
        SOPC_AddressSpace_Node* node = nodeInfo.first;
        return node != NULL &&
                node->node_class == OpcUa_NodeClass_Object &&
                SOPC_tools::toString(node->data.object.NodeId) == m_name;
    }
    const std::string m_name;
};

class OPCUA_Client {
public:
protected:
    OPCUA_Client(const string &addr) : mAddr(addr),
    mOptions{"--ca=cert/trusted/cacert.der", "--crl=cert/revoked/cacrl.der"} {}
public:
    virtual ~OPCUA_Client() = default;

    string writeValue(const string &nodeId, const SOPC_BuiltinId bType, const string& value,
            bool debug=false) {
        const string sType(std::to_string(bType));
        StringVect_t v{"./s2opc_write",
            "-e", mAddr.c_str(),
            "-n", nodeId.c_str(),
            "-t", sType.c_str()};
        for (const string&s :mOptions) {v.push_back(s);}
        v.push_back(value.c_str());

        SOPC_tools::CStringVect write_cmd(v);
        string writeLog(launch_and_check(write_cmd));
        if (debug) {
            cout << "WRITECMD=<" ;
            for (const string& s : write_cmd.cppVect) {
                cout << s  << " ";
            }
            cout << endl << "WRITELOG=<" <<writeLog << ">" << endl;
        }
        return writeLog;
    }
    string readValue(const string &nodeId, int attributeId = 13, bool debug=false) {
        StringVect_t v{"./s2opc_read",
            "-e", mAddr.c_str(),
            "-a", std::to_string(attributeId).c_str(),
            "-n", nodeId.c_str()};
        for (const string&s :mOptions) {v.push_back(s);}

        SOPC_tools::CStringVect read_cmd(v);
        string log(launch_and_check(read_cmd));
        if (debug) {
            cout << "READCMD = " ;
            for (const string& s : read_cmd.cppVect) {
                cout << s  << " ";
            }
            cout << endl << "READLOG=" <<log << ">" << endl;
        }
        return log;
    }

    string browseNode(const string &nodeId) {
        StringVect_t v{"./s2opc_browse",
            "-e", mAddr.c_str(),
            "-n", nodeId.c_str()};
        for (const string&s :mOptions) {v.push_back(s);}
        SOPC_tools::CStringVect write_cmd(v);
        return launch_and_check(write_cmd);
    }
protected:
    StringVect_t mOptions;
private:
    string mAddr;
};

class OPCUA_ClientNone : public OPCUA_Client {
public:
    OPCUA_ClientNone(const string &addr) :
        OPCUA_Client(addr) {
        mOptions.push_back("--none");
    }
    virtual ~OPCUA_ClientNone() = default;
};

class OPCUA_ClientSecu : public OPCUA_Client {
public:
    OPCUA_ClientSecu(const string &addr, const string& user = "user", const string& pwd = "password") :
        OPCUA_Client(addr) {
        static const string user_prefix("--username=");
        static const string pwd_prefix("--password=");
        StringVect_t v{"--encrypt",
            user_prefix + user, pwd_prefix + pwd,
            "--user_policy_id=username_Basic256Sha256",
            "--client_cert=cert/client_public/client_2k_cert.der",
            "--client_key=cert/client_private/client_2k_key.pem",
            "--server_cert=cert/server_public/server_2k_cert.der"
        };
        for (const string&s :v) {mOptions.push_back(s);}
    }
    virtual ~OPCUA_ClientSecu() = default;
};


struct TestReading {
    TestReading(const string& do_type, const string& do_id, uint32_t do_quality = 0):
        m_id(do_id),
        m_type(do_type),
        m_quality(do_quality),
        m_ts(0),
        m_cot(1),
        m_source("process"),
        m_comingfrom("test_source"),
        m_ts_org("genuine"),
        m_ts_validity("good"),
        m_qualityDetails(0),
        mElem(new Datapoints),
        mValue(nullptr),
        mPushed(false) {}
    void pushIntValue(const int64_t value, Readings* readings) {
        GTEST_ASSERT_EQ(mValue, nullptr);
        mValue = createIntDatapointValue("do_value", value);
        pushReading(readings);
    }
    void pushFloatValue(const double value, Readings* readings) {
        GTEST_ASSERT_EQ(mValue, nullptr);
        mValue = createFloatDatapointValue("do_value", value);
        pushReading(readings);
    }
    void pushStrValue(const string& value, Readings* readings) {
        GTEST_ASSERT_EQ(mValue, nullptr);
        mValue = createStringDatapointValue("do_value", value);
        pushReading(readings);
    }
    void addProperty(Datapoint* dp) {
        mElem->push_back(dp);
    }
    DatapointValue* getElement(const string& key) {
        for (Datapoint* dp : *mElem) {
            if (dp->getName() == key) {return &dp->getData();}
        }
        return nullptr;
    }
    void prebuild(void){
        assert(!mPushed);
        GTEST_ASSERT_NE(mValue, nullptr);
        mElem->push_back(createStringDatapointValue("do_type", m_type));
        mElem->push_back(createStringDatapointValue("do_id", m_id));
        mElem->push_back(createIntDatapointValue("do_quality", m_qualityDetails));
        mElem->push_back(createIntDatapointValue("do_ts", m_ts));
        mElem->push_back(createIntDatapointValue("do_cot", m_cot));
        mElem->push_back(createStringDatapointValue("do_source", m_source));
        mElem->push_back(createStringDatapointValue("do_comingfrom", m_comingfrom));
        mElem->push_back(createStringDatapointValue("do_ts_org", m_ts_org));
        mElem->push_back(createStringDatapointValue("do_ts_validity", m_ts_validity));
        mElem->push_back(createIntDatapointValue("do_value_quality", m_quality));
        mElem->push_back(mValue);
    }
    void pushPrebuiltReading(Readings* readings){
        DatapointValue dpv(mElem, true);
        readings->push_back(new Reading(string("reading/") + m_id, new Datapoint("data_object", dpv)));
        mPushed = true;
    }
    void pushReading(Readings* readings){
        prebuild();
        pushPrebuiltReading(readings);
    }
    string m_id;
    string m_type;
    uint32_t m_quality;
    uint32_t m_ts;
    uint32_t m_cot;
    string m_source;
    string m_comingfrom;
    string m_ts_org;
    string m_ts_validity;
    uint32_t m_qualityDetails;
    Datapoints* mElem;
    Datapoint*  mValue;
private:
    bool mPushed;
};

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
            "namespaces" : [ "urn:S2OPC:ns1" ], \
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
               "label" : "labelDPS",
               "pivot_id" : "pivotDPS",
               "pivot_type": "typeDPS",
               "protocols":[\
                  {\
                   "name":"iec104",\
                   "address":"18325-6441925",\
                   "typeid":"C_DC_TA_1"\
                  },\
                  {\
                    "name":"opcua",\
                    "address":"dps",\
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
                   "label" : "labelMVI",
                   "pivot_id" : "pivotMVI",
                   "pivot_type": "typeMVI",
                   "protocols":[\
                      {\
                        "name":"opcua",\
                        "address":"mvi",\
                        "typeid":"opcua_mvi"\
                       }\
                     ]\
                   },
                {\
                 "label" : "label2",
                 "pivot_id" : "pivotSPS",
                 "pivot_type": "type2",
                 "protocols":[\
                   {\
                     "name":"opcua",\
                     "address":"sps",\
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
