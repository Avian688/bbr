//
// Copyright (C) 2020 Marcel Marek
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include <algorithm> // min,max

#include "BbrFlavour.h"
#include "inet/transportlayer/tcp/Tcp.h"
#include "inet/transportlayer/tcp/flavours/TcpReno.h"

namespace inet {
namespace tcp {

#define MIN_REXMIT_TIMEOUT     1.0   // 1s
#define MAX_REXMIT_TIMEOUT     240   // 2 * MSL (RFC 1122)

const double BbrFlavour::PACING_GAIN_CYCLE[] = {5.0 / 4, 3.0 / 4, 1, 1, 1, 1, 1, 1};

Register_Class(BbrFlavour);

simsignal_t BbrFlavour::additiveIncreaseSignal = cComponent::registerSignal("additiveIncrease");
simsignal_t BbrFlavour::minRttSignal = cComponent::registerSignal("minRtt");
simsignal_t BbrFlavour::maxBandwidthFilterSignal = cComponent::registerSignal("maxBandwidthFilter");
simsignal_t BbrFlavour::stateSignal = cComponent::registerSignal("state");
simsignal_t BbrFlavour::pacingGainSignal = cComponent::registerSignal("pacingGain");
simsignal_t BbrFlavour::targetCwndSignal = cComponent::registerSignal("targetCwnd");
simsignal_t BbrFlavour::priorCwndSignal = cComponent::registerSignal("priorCwnd");
simsignal_t BbrFlavour::estimatedBdpSignal = cComponent::registerSignal("estimatedBdp");
simsignal_t BbrFlavour::roundCountSignal = cComponent::registerSignal("roundCount");
simsignal_t BbrFlavour::recoverSignal = cComponent::registerSignal("recover");
simsignal_t BbrFlavour::lossRecoverySignal = cComponent::registerSignal("lossRecovery");
simsignal_t BbrFlavour::highRxtSignal = cComponent::registerSignal("highRxt");
BbrFlavour::BbrFlavour() : BbrFamily(),
    state((BbrStateVariables *&)TcpAlgorithm::state)
{
}

void BbrFlavour::initialize()
{
    BbrFamily::initialize();
}

void BbrFlavour::established(bool active)
{
    //state->snd_cwnd = state->B * state->T.dbl();
    //state->snd_cwnd = 7300; //5 packets
    if(!state->m_isInitialized){
        dynamic_cast<BbrConnection*>(conn)->changeIntersendingTime(0.0000001); //do not pace intial packets as RTT is unknown

        state->snd_cwnd = 4 * state->snd_mss; // RFC 2001
        state->m_minRttStamp = simTime();
        state->m_initialCWnd = state->snd_cwnd;
        generator.seed(6);
        state->m_segmentSize = state->snd_mss;
        state->m_priorCwnd = state->snd_cwnd;
        recalculateSlowStartThreshold();
        state->m_targetCWnd = state->snd_cwnd;
        state->m_minPipeCwnd = 4 * state->m_segmentSize;
        state->m_sendQuantum = 1 * state->m_segmentSize;

        initRoundCounting();
        initFullPipe();
        enterStartup();
        initPacingRate();
        state->m_ackEpochTime = simTime();
        state->m_extraAckedWinRtt = 0;
        state->m_extraAckedIdx = 0;
        state->m_ackEpochAcked = 0;
        m_extraAcked[0] = 0;
        m_extraAcked[1] = 0;
        state->m_isInitialized = true;
    }
    //state->m_ackEpochTime = simTime();
    EV_DETAIL << "OrbTCP initial CWND is set to " << state->snd_cwnd << "\n";
    if (active) {
        // finish connection setup with ACK (possibly piggybacked on data)
        EV_INFO << "Completing connection setup by sending ACK (possibly piggybacked on data)\n";
        sendData(false);
        conn->sendAck();
    }
}

void BbrFlavour::recalculateSlowStartThreshold() {
    // RFC 2581, page 4:
    // "When a TCP sender detects segment loss using the retransmission
    // timer, the value of ssthresh MUST be set to no more than the value
    // given in equation 3:
    //
    //   ssthresh = max (FlightSize / 2, 2*SMSS)            (3)
    //
    // As discussed above, FlightSize is the amount of outstanding data in
    // the network."

    // set ssthresh to flight size / 2, but at least 2 SMSS
    // (the formula below practically amounts to ssthresh = cwnd / 2 most of the time)
//    uint32_t flight_size = state->snd_max - state->snd_una;
    //state->ssthresh = std::max(flight_size / 2, 2 * state->m_segmentSize);

    //conn->emit(ssthreshSignal, state->ssthresh);
    //saveCwnd();
}

void BbrFlavour::processRexmitTimer(TcpEventCode &event) {
    TcpTahoeRenoFamily::processRexmitTimer(event);

    if (event == TCP_E_ABORT)
        return;

    // After REXMIT timeout TCP Reno should start slow start with snd_cwnd = snd_mss.
    //
    // If calling "retransmitData();" there is no rexmit limitation (bytesToSend > snd_cwnd)
    // therefore "sendData();" has been modified and is called to rexmit outstanding data.
    //
    // RFC 2581, page 5:
    // "Furthermore, upon a timeout cwnd MUST be set to no more than the loss
    // window, LW, which equals 1 full-sized segment (regardless of the
    // value of IW).  Therefore, after retransmitting the dropped segment
    // the TCP sender uses the slow start algorithm to increase the window
    // from 1 full-sized segment to the new value of ssthresh, at which
    // point congestion avoidance again takes over."

    // begin Slow Start (RFC 2581)
    //recalculateSlowStartThreshold();
    dynamic_cast<BbrConnection*>(conn)->updateInFlight();

    saveCwnd();
    state->m_roundStart = true;

    state->snd_cwnd = state->m_segmentSize;
    conn->emit(cwndSignal, state->snd_cwnd);

    EV_INFO << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
                   << ", ssthresh=" << state->ssthresh << "\n";

    state->afterRto = true;
    dynamic_cast<BbrConnection*>(conn)->cancelPaceTimer();

    dynamic_cast<BbrConnection*>(conn)->retransmitNext(true);
    sendData(false);
}

void BbrFlavour::receivedDataAck(uint32_t firstSeqAcked)
{
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    state->m_delivered = dynamic_cast<BbrConnection*>(conn)->getDelivered();
    updateModelAndState();
    updateControlParameters();

    conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(pacingGainSignal, state->m_pacingGain);

    // Check if recovery phase has ended
      if (state->lossRecovery && state->sack_enabled) {
         if (seqGE(state->snd_una, state->recoveryPoint)) {
             EV_INFO << "Loss Recovery terminated.\n";
             dynamic_cast<BbrConnection*>(conn)->updateInFlight();
             state->lossRecovery = false;
             state->m_packetConservation = false;
             restoreCwnd();
             state->snd_cwnd = state->ssthresh;
             conn->emit(lossRecoverySignal, 0);
         }
      }
      else{
          conn->emit(lossRecoverySignal, state->snd_cwnd);
      }
    // Send data, either in the recovery mode or normal mode, this is handled by sendPendingData()
     sendData(false);
}


void BbrFlavour::receivedDuplicateAck() {
    TcpTahoeRenoFamily::receivedDuplicateAck();

    if (state->dupacks == state->dupthresh) {
            EV_INFO << "Reno on dupAcks == DUPTHRESH(=" << state->dupthresh << ": perform Fast Retransmit, and enter Fast Recovery:";

            if (state->sack_enabled) {
                // RFC 3517, page 6: "When a TCP sender receives the duplicate ACK corresponding to
                // DupThresh ACKs, the scoreboard MUST be updated with the new SACK
                // information (via Update ()).  If no previous loss event has occurred
                // on the connection or the cumulative acknowledgment point is beyond
                // the last value of RecoveryPoint, a loss recovery phase SHOULD be
                // initiated, per the fast retransmit algorithm outlined in [RFC2581].
                // The following steps MUST be taken:
                //
                // (1) RecoveryPoint = HighData
                //
                // When the TCP sender receives a cumulative ACK for this data octet
                // the loss recovery phase is terminated."

                // RFC 3517, page 8: "If an RTO occurs during loss recovery as specified in this document,
                // RecoveryPoint MUST be set to HighData.  Further, the new value of
                // RecoveryPoint MUST be preserved and the loss recovery algorithm
                // outlined in this document MUST be terminated.  In addition, a new
                // recovery phase (as described in section 5) MUST NOT be initiated
                // until HighACK is greater than or equal to the new value of
                // RecoveryPoint."
                if (state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) { // HighACK = snd_una
                    dynamic_cast<BbrConnection*>(conn)->updateInFlight();
                    state->recoveryPoint = state->snd_max; // HighData = snd_max
                    state->lossRecovery = true;
                    saveCwnd();
                    state->snd_cwnd = dynamic_cast<BbrConnection*>(conn)->getBytesInFlight() + std::max(dynamic_cast<BbrConnection*>(conn)->getLastAckedSackedBytes(), state->m_segmentSize);
                    conn->emit(lossRecoverySignal, state->snd_cwnd);
                    state->m_packetConservation = true;

                    saveCwnd(); //caled after for some reason? See GetSsthrsh?


                    conn->emit(cwndSignal, state->snd_cwnd);

                    EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
                }
            }
            // RFC 2581, page 5:
            // "After the fast retransmit algorithm sends what appears to be the
            // missing segment, the "fast recovery" algorithm governs the
            // transmission of new data until a non-duplicate ACK arrives.
            // (...) the TCP sender can continue to transmit new
            // segments (although transmission must continue using a reduced cwnd)."

            // enter Fast Recovery
            //recalculateSlowStartThreshold();
            // "set cwnd to ssthresh plus 3 * SMSS." (RFC 2581)

            EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";

            // Fast Retransmission: retransmit missing segment without waiting
            // for the REXMIT timer to expire
            //conn->retransmitOneSegment(false);
            dynamic_cast<BbrConnection*>(conn)->retransmitNext(false);
            sendData(false); //try to retransmit immediately
            conn->emit(highRxtSignal, state->highRxt);
            // Do not restart REXMIT timer.
            // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
            // Resetting the REXMIT timer is discussed in RFC 2582/3782 (NewReno) and RFC 2988.

            if (state->sack_enabled) {
                // RFC 3517, page 7: "(4) Run SetPipe ()
                //
                // Set a "pipe" variable  to the number of outstanding octets
                // currently "in the pipe"; this is the data which has been sent by
                // the TCP sender but for which no cumulative or selective
                // acknowledgment has been received and the data has not been
                // determined to have been dropped in the network.  It is assumed
                // that the data is still traversing the network path."
                //conn->setPipe();
                // RFC 3517, page 7: "(5) In order to take advantage of potential additional available
                // cwnd, proceed to step (C) below."
                if (state->lossRecovery) {
                    // RFC 3517, page 9: "Therefore we give implementers the latitude to use the standard
                    // [RFC2988] style RTO management or, optionally, a more careful variant
                    // that re-arms the RTO timer on each retransmission that is sent during
                    // recovery MAY be used.  This provides a more conservative timer than
                    // specified in [RFC2988], and so may not always be an attractive
                    // alternative.  However, in some cases it may prevent needless
                    // retransmissions, go-back-N transmission and further reduction of the
                    // congestion window."
                    // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
                    //EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                    //restartRexmitTimer();

                    // RFC 3517, page 7: "(C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
                    // segments as follows:"
                    //if (((int)state->snd_cwnd - (int)state->pipe) >= (int)state->snd_mss) // Note: Typecast needed to avoid prohibited transmissions
                    //    conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
                }
            }

            state->m_delivered = dynamic_cast<BbrConnection*>(conn)->getDelivered();
            updateModelAndState();
            updateControlParameters();

            conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
            conn->emit(cwndSignal, state->snd_cwnd);
            conn->emit(pacingGainSignal, state->m_pacingGain);

            // try to transmit new segments (RFC 2581)
            sendData(false);
        }
        else if (state->dupacks > state->dupthresh) {
            //
            // Reno: For each additional duplicate ACK received, increment cwnd by SMSS.
            // This artificially inflates the congestion window in order to reflect the
            // additional segment that has left the network
            //
            //state->snd_cwnd += state->snd_mss;

            EV_DETAIL << "Reno on dupAcks > DUPTHRESH(=" << state->dupthresh << ": Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

            // Note: Steps (A) - (C) of RFC 3517, page 7 ("Once a TCP is in the loss recovery phase the following procedure MUST be used for each arriving ACK")
            // should not be used here!

            // RFC 3517, pages 7 and 8: "5.1 Retransmission Timeouts
            // (...)
            // If there are segments missing from the receiver's buffer following
            // processing of the retransmitted segment, the corresponding ACK will
            // contain SACK information.  In this case, a TCP sender SHOULD use this
            // SACK information when determining what data should be sent in each
            // segment of the slow start.  The exact algorithm for this selection is
            // not specified in this document (specifically NextSeg () is
            // inappropriate during slow start after an RTO).  A relatively
            // straightforward approach to "filling in" the sequence space reported
            // as missing should be a reasonable approach."

            state->m_delivered = dynamic_cast<BbrConnection*>(conn)->getDelivered();
            updateModelAndState();
            updateControlParameters();

            conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
            conn->emit(cwndSignal, state->snd_cwnd);
            conn->emit(pacingGainSignal, state->m_pacingGain);


            sendData(false);
        }
}

void BbrFlavour::rttMeasurementComplete(simtime_t tSent, simtime_t tAcked)
{
    //
    // Jacobson's algorithm for estimating RTT and adaptively setting RTO.
    //
    // Note: this implementation calculates in doubles. An impl. which uses
    // 500ms ticks is available from old tcpmodule.cc:calcRetransTimer().
    //

    // update smoothed RTT estimate (srtt) and variance (rttvar)
    const double g = 0.125; // 1 / 8; (1 - alpha) where alpha == 7 / 8;
    simtime_t newRTT = tAcked - tSent;
    state->m_lastRtt = newRTT;
    state->connMinRtt = std::min(state->m_lastRtt, state->connMinRtt);

    simtime_t& srtt = state->srtt;
    simtime_t& rttvar = state->rttvar;

    simtime_t err = newRTT - srtt;

    srtt += g * err;
    rttvar += g * (fabs(err) - rttvar);

    // assign RTO (here: rexmit_timeout) a new value
    simtime_t rto = srtt + 4 * rttvar;

    if (rto > MAX_REXMIT_TIMEOUT)
        rto = MAX_REXMIT_TIMEOUT;
    else if (rto < MIN_REXMIT_TIMEOUT)
        rto = MIN_REXMIT_TIMEOUT;

    state->rexmit_timeout = rto;

    // record statistics
    EV_DETAIL << "Measured RTT=" << (newRTT * 1000) << "ms, updated SRTT=" << (srtt * 1000)
              << "ms, new RTO=" << (rto * 1000) << "ms\n";

    conn->emit(rttSignal, newRTT);
    conn->emit(srttSignal, srtt);
    conn->emit(rttvarSignal, rttvar);
    conn->emit(rtoSignal, rto);
}

void BbrFlavour::updateModelAndState()
{
    updateBottleneckBandwidth();
    updateAckAggregation();
    checkCyclePhase();
    checkFullPipe();
    checkDrain();
    updateRTprop();
    checkProbeRTT();
}

void BbrFlavour::updateControlParameters()
{
    setPacingRate(state->m_pacingGain);
    setSendQuantum();
    setCwnd();

}

void BbrFlavour::updateBottleneckBandwidth()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if(rs.m_delivered < 0 || rs.m_interval == 0){
        return;
    }

    updateRound();

    if (rs.m_deliveryRate >= m_maxBwFilter.GetBest() || !rs.m_isAppLimited)
    {
        m_maxBwFilter.Update(rs.m_deliveryRate, state->m_roundCount);
        if(rs.m_deliveryRate > state->prevMaxBandwidth){
            state->prevMaxBandwidth = rs.m_deliveryRate;
        }
    }
}

void BbrFlavour::updateAckAggregation()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    uint32_t expectedAcked;
    uint32_t extraAck;
    uint32_t epochProp;
    if (!state->m_extraAckedGain || rs.m_ackedSacked <= 0 || rs.m_delivered < 0)
    {
        return;
    }

    if (state->m_roundStart)
    {
        state->m_extraAckedWinRtt = std::min<uint32_t>(31, state->m_extraAckedWinRtt + 1);
        if (state->m_extraAckedWinRtt >= state->m_extraAckedWinRttLength)
        {
            state->m_extraAckedWinRtt = 0;
            state->m_extraAckedIdx = state->m_extraAckedIdx ? 0 : 1;
            m_extraAcked[state->m_extraAckedIdx] = 0;
        }
    }

    epochProp = simTime().dbl() - state->m_ackEpochTime.dbl();
    expectedAcked = m_maxBwFilter.GetBest() * epochProp;

    if (state->m_ackEpochAcked <= expectedAcked ||
        (state->m_ackEpochAcked + rs.m_ackedSacked >= state->m_ackEpochAckedResetThresh))
    {
        state->m_ackEpochAcked = 0;
        state->m_ackEpochTime = simTime();
        expectedAcked = 0;
    }

    state->m_ackEpochAcked = state->m_ackEpochAcked + rs.m_ackedSacked;
    extraAck = state->m_ackEpochAcked - expectedAcked;
    extraAck = std::min(extraAck, state->snd_cwnd);

    if (extraAck > m_extraAcked[state->m_extraAckedIdx])
    {
        m_extraAcked[state->m_extraAckedIdx] = extraAck;
    }
}

void BbrFlavour::checkCyclePhase()
{
    if(m_state == BbrMode_t::BBR_PROBE_BW && isNextCyclePhase())
    {
        advanceCyclePhase();
    }
}

void BbrFlavour::checkFullPipe()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (state->m_isPipeFilled || !state->m_roundStart || rs.m_isAppLimited)
    {
        return;
    }

    /* Check if Bottleneck bandwidth is still growing*/
    if (m_maxBwFilter.GetBest() >= (state->m_fullBandwidth * 1.25)) //CHECK THIS VALUE - IS DATA TYPE OK
    {
        state->m_fullBandwidth = m_maxBwFilter.GetBest();
        state->m_fullBandwidthCount = 0;
        return;
    }

    state->m_fullBandwidthCount++;
    if (state->m_fullBandwidthCount >= 3)
    {
        state->m_isPipeFilled = true;
    }
}

void BbrFlavour::checkDrain()
{
    if (m_state == BbrMode_t::BBR_STARTUP && state->m_isPipeFilled)
    {
        enterDrain();
        state->ssthresh = inFlight(1);
    }

    //Bytes in flight is per rtt
    if (m_state == BbrMode_t::BBR_DRAIN && dynamic_cast<BbrConnection*>(conn)->getBytesInFlight() <= inFlight(1))
    {
        enterProbeBW();
    }
}

void BbrFlavour::updateRTprop()
{
    state->m_minRttExpired = simTime() > (state->m_minRttStamp + state->m_minRttFilterLen);
    if (state->m_lastRtt >= 0 && (state->m_lastRtt <= state->m_minRtt || state->m_minRttExpired))
    {
        state->m_minRtt = state->m_lastRtt;
        state->m_minRttStamp = simTime();

        conn->emit(minRttSignal, state->m_minRtt);
    }
}

void BbrFlavour::checkProbeRTT()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (m_state != BbrMode_t::BBR_PROBE_RTT && state->m_minRttExpired && !state->m_idleRestart)
    {
        enterProbeRTT();
        saveCwnd();
        state->m_probeRttDoneStamp = 0;
    }

    if (m_state == BbrMode_t::BBR_PROBE_RTT)
    {
        handleProbeRTT();
    }

    if (rs.m_delivered)
    {
        state->m_idleRestart = false;
    }
}

void BbrFlavour::updateRound()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_priorDelivered >= state->m_nextRoundDelivered)
    {
        state->m_nextRoundDelivered = state->m_delivered;
        state->m_roundCount++;
        state->m_roundStart = true;
        state->m_packetConservation = false;

        conn->emit(roundCountSignal, state->m_roundCount);
    }
    else
    {
        state->m_roundStart = false;
    }

}

bool BbrFlavour::isNextCyclePhase()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    bool isFullLength = (simTime() - state->m_cycleStamp) > state->m_minRtt;
    if (state->m_pacingGain == 1)
    {
        return isFullLength;
    }
    else if (state->m_pacingGain > 1)
    {
        return isFullLength &&
               (rs.m_bytesLoss > 0 || rs.m_priorInFlight >= inFlight(state->m_pacingGain));
    }
    else
    {
        return isFullLength || rs.m_priorInFlight <= inFlight(1);
    }
}

void BbrFlavour::advanceCyclePhase()
{
    state->m_cycleStamp = simTime();
    state->m_cycleIndex = (state->m_cycleIndex + 1) % GAIN_CYCLE_LENGTH;
    state->m_pacingGain = PACING_GAIN_CYCLE[state->m_cycleIndex];
    conn->emit(pacingGainSignal, state->m_pacingGain);
}

uint32_t BbrFlavour::inFlight(double gain)
{
    if (state->m_minRtt == SIMTIME_MAX)
    {
        return state->m_initialCWnd;// * state->snd_mss; //CHECK IF WRONG
    }
    double quanta = 3 * state->m_sendQuantum;
    double estimatedBdp = ((double)m_maxBwFilter.GetBest()) * state->m_minRtt.dbl();// / 8.0;
    conn->emit(estimatedBdpSignal, estimatedBdp);

    if (m_state == BbrMode_t::BBR_PROBE_BW && state->m_cycleIndex == 0)
    {
        return (gain * estimatedBdp) + quanta + (2 * state->m_segmentSize);
    }
    return (gain * estimatedBdp) + quanta;
}

void BbrFlavour::enterDrain()
{
    setBbrState(BbrMode_t::BBR_DRAIN);
    state->m_pacingGain = (double) 1.0 / state->m_highGain;
    state->m_cWndGain = state->m_highGain;
}

void BbrFlavour::enterProbeBW()
{
    setBbrState(BbrMode_t::BBR_PROBE_BW);
    state->m_pacingGain = 1;
    state->m_cWndGain = 2;
    std::uniform_int_distribution<int> distrib(0,6);
    state->m_cycleIndex = GAIN_CYCLE_LENGTH - 1 - (int)distrib(generator);
    advanceCyclePhase();

    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void BbrFlavour::setBbrState(BbrMode_t mode)
{
    m_state = mode;
    conn->emit(stateSignal, m_state);
}

void BbrFlavour::enterProbeRTT()
{
    setBbrState(BbrMode_t::BBR_PROBE_RTT);
    state->m_pacingGain = 1;
    state->m_cWndGain = 1;

    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void BbrFlavour::handleProbeRTT()
{
    uint32_t totalBytes = state->m_delivered + dynamic_cast<BbrConnection*>(conn)->getBytesInFlight();
    state->m_appLimited = false;

    if (state->m_probeRttDoneStamp == 0 && dynamic_cast<BbrConnection*>(conn)->getBytesInFlight() <= state->m_minPipeCwnd)
    {
        state->m_probeRttDoneStamp = simTime() + state->m_probeRttDuration;
        state->m_probeRttRoundDone = false;
        state->m_nextRoundDelivered = state->m_delivered;
    }
    else if (state->m_probeRttDoneStamp != 0)
    {
        if (state->m_roundStart)
        {
            state->m_probeRttRoundDone = true;
        }
        if (state->m_probeRttRoundDone && simTime() > state->m_probeRttDoneStamp)
        {
            state->m_minRttStamp = simTime();
            restoreCwnd();
            exitProbeRTT();
        }
    }
}

void BbrFlavour::saveCwnd()
{
    if (!state->lossRecovery && m_state != BbrMode_t::BBR_PROBE_RTT)
    {
        state->m_priorCwnd = state->snd_cwnd;
    }
    else
    {
        state->m_priorCwnd = std::max(state->m_priorCwnd, state->snd_cwnd);
    }
    conn->emit(priorCwndSignal, state->m_priorCwnd);
}

void BbrFlavour::restoreCwnd()
{
    state->snd_cwnd = std::max(state->m_priorCwnd, state->snd_cwnd);
    conn->emit(cwndSignal, state->snd_cwnd);
}

void BbrFlavour::exitProbeRTT()
{
    if (state->m_isPipeFilled)
    {
        enterProbeBW();
    }
    else
    {
        enterStartup();
    }
}

void BbrFlavour::enterStartup()
{
    setBbrState(BbrMode_t::BBR_STARTUP);
    state->m_pacingGain = state->m_highGain;
    state->m_cWndGain = state->m_highGain;

    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void BbrFlavour::setPacingRate(double gain)
{
    uint32_t rate = (double) gain * (double) m_maxBwFilter.GetBest();
    rate *= (1.f - state->m_pacingMargin);
    uint32_t maxRate = 500000000;
    rate = std::min(rate, maxRate);

    if (!state->m_hasSeenRtt && state->connMinRtt != SIMTIME_MAX)
    {
        initPacingRate();
    }

    //double pace = state->m_minRtt.dbl()/(((double)rate*state->m_lastRtt.dbl())/(double)state->m_segmentSize);
    double pace = (double)1/(((double)rate)/(double)state->m_segmentSize);
    if ((state->m_isPipeFilled || pace < dynamic_cast<BbrConnection*>(conn)->getPacingRate().dbl()) && rate > 0)
    {
        dynamic_cast<BbrConnection*>(conn)->changeIntersendingTime(pace);
    }
}

void BbrFlavour::setSendQuantum()
{
    state->m_sendQuantum = 1 * state->m_segmentSize;
}

void BbrFlavour::setCwnd()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (!rs.m_ackedSacked)
    {
        goto done;
    }
    if (state->lossRecovery)
    {
        if (modulateCwndForRecovery())
        {
            goto done;
        }
    }

    updateTargetCwnd();

    if (state->m_isPipeFilled)
    {
        state->snd_cwnd = std::min(state->snd_cwnd + (uint32_t)rs.m_ackedSacked, state->m_targetCWnd);
    }
    else if (state->snd_cwnd  < state->m_targetCWnd || state->m_delivered < state->m_initialCWnd) //* snd_mss
    {
        state->snd_cwnd  = state->snd_cwnd  + rs.m_ackedSacked;
    }
    state->snd_cwnd  = std::max(state->snd_cwnd , state->m_minPipeCwnd);
    conn->emit(cwndSignal, state->snd_cwnd);
done:
    modulateCwndForProbeRTT();
}

bool BbrFlavour::modulateCwndForRecovery()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_bytesLoss > 0)
    {
       state->snd_cwnd = std::max((int)state->snd_cwnd  - (int)rs.m_bytesLoss, (int)state->m_segmentSize);
       conn->emit(cwndSignal, state->snd_cwnd);
    }

    if (state->m_packetConservation)
    {
       state->snd_cwnd = std::max(state->snd_cwnd , dynamic_cast<BbrConnection*>(conn)->getBytesInFlight() + rs.m_ackedSacked);
       conn->emit(cwndSignal, state->snd_cwnd);
       return true;
    }
    return false;
}

void BbrFlavour::modulateCwndForProbeRTT()
{
    if (m_state == BbrMode_t::BBR_PROBE_RTT)
    {
        state->snd_cwnd = std::min(state->snd_cwnd, state->m_minPipeCwnd);
        conn->emit(cwndSignal, state->snd_cwnd);
    }
}

void BbrFlavour::initPacingRate()
{
    //if (!tcb->m_pacing)
    //{
    //    NS_LOG_WARN("BBR must use pacing");
    //    tcb->m_pacing = true;
    //}

    simtime_t rtt;
    if (state->connMinRtt != SIMTIME_MAX)
    {
        if (state->connMinRtt < 0.001){
            rtt = 0.001;
        }
        else{
            rtt = state->connMinRtt;
        }
        state->m_hasSeenRtt = true;
    }
    else
    {
        rtt = SimTime(0.001);
    }

    uint32_t nominalBandwidth = (state->snd_cwnd / rtt.dbl()); //* 8 / rtt.dbl());
    if((state->m_pacingGain * (double) nominalBandwidth) > 0){
        //double pace = rtt.dbl()/(((state->m_pacingGain *(double)nominalBandwidth)*rtt.dbl())/(double)state->m_segmentSize);
        double pace = 1/((state->m_pacingGain *(double)nominalBandwidth)/(double)state->m_segmentSize);
        dynamic_cast<BbrConnection*>(conn)->changeIntersendingTime(pace);
    }
    m_maxBwFilter = MaxBandwidthFilter_t(state->m_bandwidthWindowLength, state->snd_cwnd / rtt.dbl(), 0);// * 8 / rtt.dbl(), 0);
    state->prevMaxBandwidth = state->snd_cwnd / rtt.dbl();
    //std::cout << "\n SETTING FILTER TO LENGTH OF " << state->m_bandwidthWindowLength << endl;
}

void BbrFlavour::updateTargetCwnd()
{
    state->m_targetCWnd = inFlight(state->m_cWndGain);// + ackAggregationCwnd();
    conn->emit(targetCwndSignal, state->m_targetCWnd);
}

uint32_t BbrFlavour::ackAggregationCwnd()
{
    uint32_t maxAggrBytes; // MaxBW * 0.1 secs
    uint32_t aggrCwndBytes = 0;

    if (state->m_extraAckedGain && state->m_isPipeFilled)
    {
        maxAggrBytes = m_maxBwFilter.GetBest() / 10;
        aggrCwndBytes = state->m_extraAckedGain * std::max(m_extraAcked[0], m_extraAcked[1]);
        aggrCwndBytes = std::min(aggrCwndBytes, maxAggrBytes);
    }
    return aggrCwndBytes;
}

void BbrFlavour::initRoundCounting()
{
    state->m_nextRoundDelivered = 0;
    state->m_roundStart = false;
    state->m_roundCount = 0;
}

void BbrFlavour::initFullPipe()
{
    state->m_isPipeFilled = false;
    state->m_fullBandwidth = 0;
    state->m_fullBandwidthCount = 0;
}

} // namespace tcp
} // namespace inet
