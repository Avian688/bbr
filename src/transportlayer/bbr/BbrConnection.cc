//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include "BbrConnection.h"

namespace inet {
namespace tcp {

Define_Module(BbrConnection);

BbrConnection::BbrConnection()
{
}

BbrConnection::~BbrConnection()
{
}

void BbrConnection::initConnection(TcpOpenCommand *openCmd)
{
    TcpPacedConnection::initConnection(openCmd);
}

TcpConnection *BbrConnection::cloneListeningConnection()
{
    auto moduleType = cModuleType::get("bbr.transportlayer.bbr.BbrConnection");
    int newSocketId = getEnvir()->getUniqueNumber();
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", newSocketId);
    auto conn = check_and_cast<BbrConnection *>(moduleType->createScheduleInit(submoduleName, tcpMain));
    conn->TcpConnection::initConnection(tcpMain, newSocketId);
    conn->initClonedConnection(this);
    return conn;
}

void BbrConnection::initClonedConnection(TcpConnection *listenerConn)
{
    TcpPacedConnection::initClonedConnection(listenerConn);
}

} // namespace tcp
} // namespace inet
