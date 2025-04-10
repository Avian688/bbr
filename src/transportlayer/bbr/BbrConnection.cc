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

#include <algorithm>
#include "BbrConnection.h"

#include <inet/transportlayer/tcp/TcpSendQueue.h>
#include <inet/transportlayer/tcp/TcpAlgorithm.h>
#include <inet/transportlayer/tcp/TcpReceiveQueue.h>
#include <inet/transportlayer/tcp/TcpSackRexmitQueue.h>

#include "../bbr/flavours/BbrFlavour.h"

namespace inet {
namespace tcp {

Define_Module(BbrConnection);

BbrConnection::BbrConnection() {
    // TODO Auto-generated constructor stub

}

BbrConnection::~BbrConnection() {
    // TODO Auto-generated destructor stub
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

bool BbrConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";
    uint64_t previousDelivered = m_delivered;  //RATE SAMPLER SPECIFIC STUFF
    uint32_t previousLost = m_bytesLoss; //TODO Create Sack method to get exact amount of lost packets
    uint32_t priorInFlight = m_bytesInFlight;//get current BytesInFlight somehow
    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
    //updateInFlight();

    // ECN
    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpHeader->getEceBit() == true)
            EV_INFO << "Received packet with ECE\n";

        state->gotEce = tcpHeader->getEceBit();
    }

    //
    //"
    //  If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
    //  Any segments on the retransmission queue which are thereby
    //  entirely acknowledged are removed.  Users should receive
    //  positive acknowledgments for buffers which have been SENT and
    //  fully acknowledged (i.e., SEND buffer should be returned with
    //  "ok" response).  If the ACK is a duplicate
    //  (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
    //  something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
    //  drop the segment, and return.
    //
    //  If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
    //  updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
    //  SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
    //  SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
    //
    //  Note that SND.WND is an offset from SND.UNA, that SND.WL1
    //  records the sequence number of the last segment used to update
    //  SND.WND, and that SND.WL2 records the acknowledgment number of
    //  the last segment used to update SND.WND.  The check here
    //  prevents using old segments to update the window.
    //"
    // Note: should use SND.MAX instead of SND.NXT in above checks
    //
    if (seqGE(state->snd_una, tcpHeader->getAckNo())) {
        //
        // duplicate ACK? A received TCP segment is a duplicate ACK if all of
        // the following apply:
        //    (1) snd_una == ackNo
        //    (2) segment contains no data
        //    (3) there's unacked data (snd_una != snd_max)
        //
        // Note: ssfnet uses additional constraint "window is the same as last
        // received (not an update)" -- we don't do that because window updates
        // are ignored anyway if neither seqNo nor ackNo has changed.
        //
        if (state->snd_una == tcpHeader->getAckNo() && payloadLength == 0 && state->snd_una != state->snd_max) {
            state->dupacks++;

            emit(dupAcksSignal, state->dupacks);

            // we need to update send window even if the ACK is a dupACK, because rcv win
            // could have been changed if faulty data receiver is not respecting the "do not shrink window" rule
            if (rack_enabled)
            {
             uint32_t tser = state->ts_recent;
             simtime_t rtt = dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRtt();

            // Get information of the latest packet (cumulatively)ACKed packet and update RACK parameters
            if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
            {
                TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(tcpHeader->getAckNo());
                m_rack->updateStats(tser, skbRegion.rexmitted, skbRegion.m_lastSentTime, tcpHeader->getAckNo(), state->snd_nxt, rtt);
            }
            else{  // Get information of the latest packet (Selectively)ACKed packet and update RACK parameters
                uint32_t highestSacked;
                highestSacked = rexmitQueue->getHighestSackedSeqNum();
                if(rexmitQueue->findRegion(highestSacked)){
                    TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(highestSacked);
                    m_rack->updateStats(tser, skbRegion.rexmitted,  skbRegion.m_lastSentTime, highestSacked, state->snd_nxt, rtt);
                }
            }

            // Check if TCP will be exiting loss recovery
            bool exiting = false;
            if (state->lossRecovery && dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRecoveryPoint() <= tcpHeader->getAckNo())
            {
                exiting = true;
            }

            m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, tcpHeader->getAckNo(), rexmitQueue->getTotalAmountOfSackedBytes(), 3, exiting, state->lossRecovery);
            }
            scoreboardUpdated = false;


            updateWndInfo(tcpHeader);

            if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {
                skbDelivered(tcpHeader->getAckNo());
            }
//
            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;
////
            updateInFlight();
////
            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;
////
            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            tcpAlgorithm->receivedDuplicateAck();

            sendPendingData();

            m_reorder = false;
            //
            // Update m_sndFack if possible
            if (fack_enabled || rack_enabled)
            {
              if (tcpHeader->getAckNo() > m_sndFack)
                {
                  m_sndFack = tcpHeader->getAckNo();
                }
              // Packet reordering seen
              else if (tcpHeader->getAckNo() < m_sndFack)
                {
                  m_reorder = true;
                }
            }

        }
        else {
            // if doesn't qualify as duplicate ACK, just ignore it.
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo()){
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                }
                else if (state->snd_una == state->snd_max) {
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
                }
            }
            // reset counter
            state->dupacks = 0;
            
            emit(dupAcksSignal, state->dupacks);
        }
    }
    else if (seqLE(tcpHeader->getAckNo(), state->snd_max)) {
        // ack in window.
        uint32_t old_snd_una = state->snd_una;
        state->snd_una = tcpHeader->getAckNo();

        emit(unackedSignal, state->snd_max - state->snd_una);

        // after retransmitting a lost segment, we may get an ack well ahead of snd_nxt
        if (seqLess(state->snd_nxt, state->snd_una))
            state->snd_nxt = state->snd_una;

        // RFC 1323, page 36:
        // "If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
        // Also compute a new estimate of round-trip time.  If Snd.TS.OK
        // bit is on, use my.TSclock - SEG.TSecr; otherwise use the
        // elapsed time since the first segment in the retransmission
        // queue was sent.  Any segments on the retransmission queue
        // which are thereby entirely acknowledged."
        if (state->ts_enabled)
            tcpAlgorithm->rttMeasurementCompleteUsingTS(getTSecr(tcpHeader));
        // Note: If TS is disabled the RTT measurement is completed in TcpBaseAlg::receivedDataAck()

        uint32_t discardUpToSeq = state->snd_una;
        // our FIN acked?
        if (state->send_fin && tcpHeader->getAckNo() == state->snd_fin_seq + 1) {
            // set flag that our FIN has been acked
            EV_DETAIL << "ACK acks our FIN\n";
            state->fin_ack_rcvd = true;
            discardUpToSeq--; // the FIN sequence number is not real data
        }

        if (rack_enabled)
        {
          uint32_t tser = state->ts_recent;
          simtime_t rtt = dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRtt();

        // Get information of the latest packet (cumulatively)ACKed packet and update RACK parameters
        if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
        {
            TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(tcpHeader->getAckNo());
            m_rack->updateStats(tser, skbRegion.rexmitted, skbRegion.m_lastSentTime, tcpHeader->getAckNo(), state->snd_nxt, rtt);
        }
        else // Get information of the latest packet (Selectively)ACKed packet and update RACK parameters
        {
            uint32_t highestSacked;
            highestSacked = rexmitQueue->getHighestSackedSeqNum();
            if(rexmitQueue->findRegion(highestSacked)){
                TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(highestSacked);
                m_rack->updateStats(tser, skbRegion.rexmitted,  skbRegion.m_lastSentTime, highestSacked, state->snd_nxt, rtt);
            }
        }

          // Check if TCP will be exiting loss recovery
          bool exiting = false;
          if (state->lossRecovery && dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRecoveryPoint() <= tcpHeader->getAckNo())
            {
              exiting = true;
            }

          m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, old_snd_una, rexmitQueue->getTotalAmountOfSackedBytes(), 3, exiting, state->lossRecovery);
        }
        scoreboardUpdated = false;

        // acked data no longer needed in send queue

        // acked data no longer needed in rexmit queue
        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {
            skbDelivered(tcpHeader->getAckNo());
        }

        // acked data no longer needed in send queue
        sendQueue->discardUpTo(discardUpToSeq);
        enqueueData();

        // acked data no longer needed in rexmit queue
        if (state->sack_enabled){
            rexmitQueue->discardUpTo(discardUpToSeq);
        }

        updateWndInfo(tcpHeader);

        // if segment contains data, wait until data has been forwarded to app before sending ACK,
        // otherwise we would use an old ACKNo
        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {

            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;

            updateInFlight();

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;
            // notify

            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            dynamic_cast<BbrFamily*>(tcpAlgorithm)->receivedDataAck(old_snd_una);
            // in the receivedDataAck we need the old value
            state->dupacks = 0;

            sendPendingData();

            m_reorder = false;
            //
            // Update m_sndFack if possible
            if (fack_enabled || rack_enabled)
            {
              if (tcpHeader->getAckNo() > m_sndFack)
                {
                  m_sndFack = tcpHeader->getAckNo();
                }
              // Packet reordering seen
              else if (tcpHeader->getAckNo() < m_sndFack)
                {
                  m_reorder = true;
                }
            }

            emit(dupAcksSignal, state->dupacks);
            emit(mDeliveredSignal, m_delivered);
        }
    }
    else {
        ASSERT(seqGreater(tcpHeader->getAckNo(), state->snd_max)); // from if-ladder

        // send an ACK, drop the segment, and return.
        tcpAlgorithm->receivedAckForDataNotYetSent(tcpHeader->getAckNo());
        state->dupacks = 0;

        emit(dupAcksSignal, state->dupacks);
        return false; // means "drop"
    }
    return true;
}


}
}
