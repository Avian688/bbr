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

#ifndef TRANSPORTLAYER_BBR_BBRCONNECTION_H_
#define TRANSPORTLAYER_BBR_BBRCONNECTION_H_

#include <queue>
#include <inet/common/INETUtils.h>
#include <inet/transportlayer/tcp/TcpConnection.h>
#include <inet/networklayer/common/EcnTag_m.h>
#include <inet/transportlayer/common/L4Tools.h>
#include <inet/networklayer/common/DscpTag_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/TosTag_m.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/networklayer/contract/IL3AddressType.h>
#include "SkbInfo_m.h"
namespace inet {
namespace tcp {

class BbrConnection : public TcpConnection {
public:
    static simsignal_t mDeliveredSignal;
    static simsignal_t mFirstSentTimeSignal;
    static simsignal_t mLastSentTimeSignal;
    static simsignal_t msendElapsedSignal;
    static simsignal_t mackElapsedSignal;
    static simsignal_t mbytesInFlightSignal;
    static simsignal_t mbytesInFlightTotalSignal;
    static simsignal_t mbytesLossSignal;

    struct RateSample {
        uint32_t m_deliveryRate;
        bool m_isAppLimited;
        simtime_t m_interval;
        uint32_t m_delivered;
        uint32_t m_priorDelivered;
        simtime_t m_priorTime;
        simtime_t m_sendElapsed;
        simtime_t m_ackElapsed;
        uint32_t m_bytesLoss;
        uint32_t m_priorInFlight;
        uint32_t m_ackedSacked;
    };

    BbrConnection();
    virtual ~BbrConnection();
protected:
    virtual TcpEventCode processSegment1stThru8th(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;
    virtual bool processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;

    virtual void initConnection(TcpOpenCommand *openCmd) override;
    virtual void initClonedConnection(TcpConnection *listenerConn) override;
    virtual void configureStateVariables() override;
    virtual void process_SEND(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;
    virtual TcpConnection *cloneListeningConnection() override;

    virtual void updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt);

    virtual void calculateAppLimited();

public:
    virtual bool processTimer(cMessage *msg) override;
    virtual uint32_t sendSegment(uint32_t bytes) override;
    virtual bool sendData(uint32_t congestionWindow) override;
    virtual void sendToIP(Packet *packet, const Ptr<TcpHeader> &tcpseg) override;
    virtual void changeIntersendingTime(simtime_t _intersendingTime);

    virtual simtime_t getFirstSent();

    virtual simtime_t getDeliveredTime();

    virtual uint32_t getDelivered();

    virtual RateSample getRateSample();

    virtual uint32_t getBytesInFlight();

    virtual simtime_t getPacingRate();

    virtual uint32_t getLastAckedSackedBytes();

    virtual void addSkbInfoTags(const Ptr<TcpHeader> &tcpHeader, uint32_t payloadBytes);

    virtual void setPipe() override;

    virtual void skbDelivered(const Ptr<const SkbInfo> skbInfo);

    virtual void retransmitOneSegment(bool called_at_rto) override;

    virtual bool sendDataDuringLossRecovery(uint32_t congestionWindow);

    virtual void cancelPaceTimer();

    virtual void updateInFlight();

    virtual void sendPendingData();

    virtual void retransmitNext(bool timeout);
private:
    virtual void processPaceTimer();

    void addPacket(Packet *packet);
protected:
    cOutVector paceValueVec;
    cOutVector bufferedPacketsVec;
    bool pace;
    simtime_t paceStart;
    simtime_t timerDifference;

    uint32_t m_lastAckedSackedBytes;

    uint32_t m_delivered;
    simtime_t m_deliveredTime;
    uint32_t m_rateDelivered;
    simtime_t m_rateInterval;
    simtime_t m_firstSentTime;

    RateSample m_rateSample;
    uint32_t m_bytesInFlight;
    uint32_t m_bytesLoss;

    uint32_t m_appLimited; //NOT NEEDED
    bool m_rateAppLimited; //NOT NEEDED
    bool m_txItemDelivered; //NOT NEEDED

    uint32_t calcBytesInFlight;
    uint32_t bufferedBytes;

    bool retransmitOnePacket;
    bool retransmitAfterTimeout;

public:
    virtual void sendSkbInfoAck(const Ptr<const SkbInfo> skbInfo);
public:
    std::queue<Packet*> packetQueue;
    //std::queue<uint32_t> packetsToSendQueue;
    cMessage *paceMsg;
    simtime_t intersendingTime;

};

}
}

#endif /* TRANSPORTLAYER_BBR_BBRCONNECTION_H_ */
