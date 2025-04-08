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

#include "BbrFamily.h"

namespace inet {
namespace tcp {

std::string BbrFamilyStateVariables::str() const
{
    std::stringstream out;
    out << TcpTahoeRenoFamilyStateVariables::str();
    return out.str();
}

std::string BbrFamilyStateVariables::detailedInfo() const
{
    std::stringstream out;
    out << TcpTahoeRenoFamilyStateVariables::detailedInfo();
    return out.str();
}

// ---

BbrFamily::BbrFamily() : TcpPacedFamily(),
    state((BbrFamilyStateVariables *&)TcpPacedFamily::state)
{
}

void BbrFamily::receivedDataAck(uint32_t firstSeqAcked)
{
    TcpPacedFamily::receivedDataAck(firstSeqAcked);
}

void BbrFamily::receivedDuplicateAck() {
    TcpPacedFamily::receivedDuplicateAck();
}

} // namespace tcp
} // namespace inet
