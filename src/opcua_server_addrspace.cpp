/*
 * Fledge Power north plugin.
 *
 * Copyright (c) 2022 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

#include "opcua_server_addrspace.h"

// System headers
#include <stdio.h>

extern "C" {
// S2OPC headers
#include "s2opc/common/sopc_macros.h"
#include "s2opc/common/sopc_common.h"
#include "s2opc/common/sopc_enums.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/opcua_statuscodes.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/clientserver/sopc_address_space.h"
}

// Fledge headers
#include <config_category.h>
#include <logger.h>

namespace
{
s2opc_north::NodeVect_t getNS0(void)
{
    s2opc_north::NodeVect_t result;

    const uint32_t nbNodes(SOPC_Embedded_AddressSpace_nNodes_nano);
    SOPC_AddressSpace_Node* nodes(SOPC_Embedded_AddressSpace_Nodes_nano);

    for (uint32_t i = 0 ; i < nbNodes; i++)
    {
        SOPC_AddressSpace_Node* node(nodes + i);
        result.push_back(node);
    }

    return result;
}

} // namespace

namespace s2opc_north
{
/**************************************************************************/
Server_AddrSpace::
Server_AddrSpace(const std::string& json):
    nodes(getNS0())
{
#warning "TODO : Add possibility to setup nano/mbedded ns0"
#warning "TODO : fill address space!"
}

/**************************************************************************/
Server_AddrSpace::
~ Server_AddrSpace(void)
{
    // Note: nodes are freed automatically (See call to ::SOPC_AddressSpace_Create)
}

} //namespace s2opc_north

