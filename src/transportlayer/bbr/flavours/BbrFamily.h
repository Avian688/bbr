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

#ifndef INET_TRANSPORTLAYER_TCP_FLAVOURS_BBRFAMILY_H_
#define INET_TRANSPORTLAYER_TCP_FLAVOURS_BBRFAMILY_H_

#include "BbrFamilyState_m.h"
#include "../BbrConnection.h"
#include "inet/transportlayer/tcp/flavours/TcpTahoeRenoFamily.h"

namespace inet {
namespace tcp {
/**
 * Provides utility functions to implement Hpcc.
 */
class BbrFamily : public TcpTahoeRenoFamily
{
  protected:
    BbrFamilyStateVariables *& state; // alias to TcpAlgorithm's 'state'

  public:
    /** Ctor */
    BbrFamily();

    virtual void receivedDataAck(uint32_t firstSeqAcked, const Ptr<const SkbInfo> skbInfo);

    virtual void receiveSeqChanged(const Ptr<const SkbInfo> skbInfo);

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck() override;

    virtual simtime_t getConnMinRtt() { return state->connMinRtt;};

};

} // namespace tcp
} // namespace inet

#endif
