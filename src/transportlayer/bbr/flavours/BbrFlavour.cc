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

        if (state->increased_IW_enabled && state->syn_rexmit_count == 0) {
                state->snd_cwnd = 4 * state->snd_mss;//std::min(4 * state->snd_mss, std::max(2 * state->snd_mss, (uint32_t)4380));
                EV_DETAIL << "Enabled Increased Initial Window, CWND is set to " << state->snd_cwnd << "\n";
            }
            // RFC 2001, page 3:
            // " 1.  Initialization for a given connection sets cwnd to one segment
            // and ssthresh to 65535 bytes."
            else
                state->snd_cwnd = state->snd_mss; // RFC 2001
        state->m_minRttStamp = simTime();
        state->m_initialCWnd = state->snd_cwnd;
        generator.seed(4);
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
        if (!sendData(false)) // FIXME - This condition is never true because the buffer is empty (at this time) therefore the first ACK is never piggyback on data
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
    uint32_t flight_size = std::min(state->snd_cwnd, state->snd_wnd); // FIXME - Does this formula computes the amount of outstanding data?
//    uint32_t flight_size = state->snd_max - state->snd_una;
    state->ssthresh = std::max(flight_size / 2, 2 * state->m_segmentSize);

    conn->emit(ssthreshSignal, state->ssthresh);
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
    //state->snd_cwnd = state->m_segmentSize;
    saveCwnd();
    state->m_roundStart = true;
    conn->emit(cwndSignal, state->snd_cwnd);

    EV_INFO << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
                   << ", ssthresh=" << state->ssthresh << "\n";

    state->afterRto = true;

    conn->retransmitOneSegment(true);
}

void BbrFlavour::receivedDataAck(uint32_t firstSeqAcked, const Ptr<const SkbInfo> skbInfo)
{
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    state->m_delivered = dynamic_cast<BbrConnection*>(conn)->getDelivered();
    if (state->lossRecovery) {
        saveCwnd();
    }
    updateModelAndState();
    updateControlParameters();
    conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(pacingGainSignal, state->m_pacingGain);

     // Check if recovery phase has ended
     if (state->lossRecovery && state->sack_enabled) {
         if (seqGE(state->snd_una, state->recoveryPoint)) {
             EV_INFO << "Loss Recovery terminated.\n";
             state->lossRecovery = false;
             conn->emit(lossRecoverySignal, 0);
         }
     }

     // Send data, either in the recovery mode or normal mode
     if (state->lossRecovery) {
         // RFC 3517, page 7: "(C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
         // segments as follows:"
         //if (((int) (state->snd_cwnd / state->m_segmentSize)
         //        - (int) (state->pipe / (state->m_segmentSize))) >= 1) // Note: Typecast needed to avoid prohibited transmissions
         conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
         state->m_packetConservation = true;
     } else {
         sendData(false);
     }
}


void BbrFlavour::receivedDuplicateAck() {
    TcpTahoeRenoFamily::receivedDuplicateAck();

    if (state->lossRecovery) {
        saveCwnd();
    }

    if (state->dupacks >= state->dupthresh) {
        if (!state->lossRecovery
                && (state->recoveryPoint == 0
                        || seqGE(state->snd_una, state->recoveryPoint))) {

            state->recoveryPoint = state->snd_max; // HighData = snd_max
            state->lossRecovery = true;
            EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
            conn->emit(lossRecoverySignal, 1);

            // enter Fast Recovery
            //recalculateSlowStartThreshold();
            // "set cwnd to ssthresh plus 3 * SMSS." (RFC 2581)
            saveCwnd();
            conn->emit(cwndSignal, state->snd_cwnd);

            EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh="
                             << state->ssthresh << "\n";

            // Fast Retransmission: retransmit missing segment without waiting
            // for the REXMIT timer to expire
            conn->retransmitOneSegment(false);
            conn->emit(highRxtSignal, state->highRxt);
        }

        conn->emit(cwndSignal, state->snd_cwnd);
        conn->emit(ssthreshSignal, state->ssthresh);

    }


    updateModelAndState();
    updateControlParameters();

    if (state->lossRecovery) {
        conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
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
    state->connMinRtt = std::min(state->connMinRtt, newRTT);

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
    double estimatedBdp = m_maxBwFilter.GetBest() * state->m_minRtt.dbl();// / 8.0;

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
    conn->emit(pacingGainSignal, state->m_pacingGain);
    state->m_cWndGain = 2;
    std::uniform_int_distribution<int> distrib(0,6);
    state->m_cycleIndex = GAIN_CYCLE_LENGTH - 1 - (int)distrib(generator);
    advanceCyclePhase();
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
    conn->emit(pacingGainSignal, state->m_pacingGain);
    state->m_cWndGain = 1;
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
    conn->emit(pacingGainSignal, state->m_pacingGain);
    state->m_cWndGain = state->m_highGain;
}

void BbrFlavour::setPacingRate(double gain)
{
    uint32_t rate = (double) gain * (double) m_maxBwFilter.GetBest();
    rate *= (1.f - state->m_pacingMargin);
    //rate = std::min(rate, tcb->m_maxPacingRate);

    if (!state->m_hasSeenRtt && state->connMinRtt != SIMTIME_MAX)
    {
        initPacingRate();
    }

    //double pace = state->m_minRtt.dbl()/(((double)rate*state->m_minRtt.dbl())/(double)state->m_segmentSize);
    double pace = (double)1/(((double)rate)/(double)state->m_segmentSize);
    if ((state->m_isPipeFilled || pace <= dynamic_cast<BbrConnection*>(conn)->getPacingRate().dbl()) && rate > 0)
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

done:
    modulateCwndForProbeRTT();
}

bool BbrFlavour::modulateCwndForRecovery()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_bytesLoss > 0)
    {
       state->snd_cwnd = std::max((int)state->snd_cwnd  - (int)rs.m_bytesLoss, (int)state->m_segmentSize);
    }

    if (state->m_packetConservation)
    {
        state->snd_cwnd = std::max(state->snd_cwnd , dynamic_cast<BbrConnection*>(conn)->getBytesInFlight() + rs.m_ackedSacked);
       return true;
    }
    return false;
}

void BbrFlavour::modulateCwndForProbeRTT()
{
    if (m_state == BbrMode_t::BBR_PROBE_RTT)
    {
        state->snd_cwnd = std::min(state->snd_cwnd, state->m_minPipeCwnd);
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

