//
// Copyright (C) 2020 Marcel Marek
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include <algorithm> // min,max

#include "Bbr3Flavour.h"
#include "inet/transportlayer/tcp/Tcp.h"
#include "inet/transportlayer/tcp/flavours/TcpReno.h"

namespace inet {
namespace tcp {

#define MIN_REXMIT_TIMEOUT     0.2   // 1s
#define MAX_REXMIT_TIMEOUT     240   // 2 * MSL (RFC 1122)

const double Bbr3Flavour::PACING_GAIN_CYCLE[] = {5.0 / 4,  91.0 / 100, 1, 1 };

Register_Class(Bbr3Flavour);

simsignal_t Bbr3Flavour::additiveIncreaseSignal = cComponent::registerSignal("additiveIncrease");
simsignal_t Bbr3Flavour::minRttSignal = cComponent::registerSignal("minRtt");
simsignal_t Bbr3Flavour::connMinRttSignal = cComponent::registerSignal("connMinRtt");
simsignal_t Bbr3Flavour::maxBandwidthFilterSignal = cComponent::registerSignal("maxBandwidthFilter");
simsignal_t Bbr3Flavour::stateSignal = cComponent::registerSignal("state");
simsignal_t Bbr3Flavour::pacingGainSignal = cComponent::registerSignal("pacingGain");
simsignal_t Bbr3Flavour::targetCwndSignal = cComponent::registerSignal("targetCwnd");
simsignal_t Bbr3Flavour::priorCwndSignal = cComponent::registerSignal("priorCwnd");
simsignal_t Bbr3Flavour::estimatedBdpSignal = cComponent::registerSignal("estimatedBdp");
simsignal_t Bbr3Flavour::roundCountSignal = cComponent::registerSignal("roundCount");
simsignal_t Bbr3Flavour::recoverSignal = cComponent::registerSignal("recover");
simsignal_t Bbr3Flavour::lossRecoverySignal = cComponent::registerSignal("lossRecovery");
simsignal_t Bbr3Flavour::highRxtSignal = cComponent::registerSignal("highRxt");
simsignal_t Bbr3Flavour::recoveryPointSignal = cComponent::registerSignal("recoveryPoint");
simsignal_t Bbr3Flavour::nextRoundDeliveredSignal = cComponent::registerSignal("nextRoundDelivered");
simsignal_t Bbr3Flavour::restoreCwndSignal = cComponent::registerSignal("restoreCwnd");

Bbr3Flavour::Bbr3Flavour() : BbrFamily(),
    state((BbrStateVariables *&)TcpAlgorithm::state)
{
}

const char* const Bbr3Flavour::BbrModeName[BBR_PROBE_RTT + 1] = {
    "BBR_STARTUP",
    "BBR_DRAIN",
    "BBR_PROBE_BW",
    "BBR_PROBE_RTT",
};


const char* const Bbr3Flavour::BbrCycleName[BBR_BW_PROBE_REFILL + 1] = {
    "BBR_BW_PROBE_UP",
    "BBR_BW_PROBE_DOWN",
    "BBR_BW_PROBE_CRUISE",
    "BBR_BW_PROBE_REFILL",
};

void Bbr3Flavour::initialize()
{
    BbrFamily::initialize();
}

void Bbr3Flavour::established(bool active)
{
    if(!state->m_isInitialized){
        dynamic_cast<BbrConnection*>(conn)->changeIntersendingTime(0.0000001); //do not pace intial packets as RTT is unknown

        state->snd_cwnd = 4 * state->snd_mss; // RFC 2001
        state->m_rtProp = state->srtt != 0 ? state->srtt : SIMTIME_MAX;
        state->m_probeRttMinStamp = simTime();
        state->m_rtPropStamp = simTime();
        state->m_probeRttDoneStamp = simTime();
        state->m_initialCWnd = state->snd_cwnd;
        state->m_segmentSize = state->snd_mss;
        state->m_priorCwnd = state->snd_cwnd;
        state->m_cycleIndex = 2;
        recalculateSlowStartThreshold();
        state->m_targetCWnd = state->snd_cwnd;
        state->m_minPipeCwnd = 4 * state->m_segmentSize;
        state->m_sendQuantum = 1 * state->m_segmentSize;

        initRoundCounting();
        initFullPipe();
        m_state = BbrMode_t::BBR_STARTUP;
        conn->emit(stateSignal, m_state);
        state->m_pacingGain = state->m_highGain;
        state->m_cWndGain = state->m_highGain;

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
    EV_DETAIL << "BBR initial CWND is set to " << state->snd_cwnd << "\n";
    if (active) {
        // finish connection setup with ACK (possibly piggybacked on data)
        EV_INFO << "Completing connection setup by sending ACK (possibly piggybacked on data)\n";
        sendData(false);
        conn->sendAck();
    }
}

void Bbr3Flavour::bbr_main() {
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    struct bbr_context ctx = { 0 };

    state->m_delivered = dynamic_cast<TcpPacedConnection*>(conn)->getDelivered();
    state->m_txItemDelivered = dynamic_cast<TcpPacedConnection*>(conn)->getTxItemDelivered();
    state->maxBw = bbr_max_bw();

    bbr_update_round_start();
    bbr_calculate_bw_sample(&ctx);
    bbr_update_latest_delivery_signals(&ctx);
    bbr_update_model(&ctx);
    bbr_update_gains();
    state->wildcard = rs.m_bytesLoss;
    bbr_set_pacing_rate(state->m_pacingGain);
    setSendQuantum();
    bbr_set_cwnd();
    bbr_bound_cwnd_for_inflight_model();
    bbr_advance_latest_delivery_signals(&ctx);
}

void Bbr3Flavour::recalculateSlowStartThreshold() {
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

    //saveCwnd();
    conn->emit(ssthreshSignal, state->ssthresh);
}

void Bbr3Flavour::processRexmitTimer(TcpEventCode &event) {

    //if(state->lossRecovery){
    //bbr_exit_loss_recovery();
        //std::cout << "\n EXITED LOSS RECOVERY" << endl;
    //}

    TcpPacedFamily::processRexmitTimer(event);

    bbr_save_cwnd();
    state->m_roundStart = true;
    bbr_reset_full_bw();
    if (bbr_is_probing_bandwidth() && m_inflightLo == std::numeric_limits<uint32_t>::max ())
    {
      m_inflightLo = std::max(state->snd_cwnd, state->m_priorCwnd);
    }
    state->snd_cwnd = state->snd_mss*4;
    conn->emit(cwndSignal, state->snd_cwnd);

    EV_INFO << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
                   << ", ssthresh=" << state->ssthresh << "\n";

    state->afterRto = true;
    tcp_state = CA_LOSS;
    dynamic_cast<TcpPacedConnection*>(conn)->cancelPaceTimer();
    sendData(false);
}

void Bbr3Flavour::receivedDataAck(uint32_t firstSeqAcked)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    //dynamic_cast<BbrConnection*>(conn)->updateInFlight();
    // Check if recovery phase has ended

    if (state->lossRecovery && state->sack_enabled) {
        if (seqGE(state->snd_una, state->recoveryPoint)) {
            EV_INFO << "Loss Recovery terminated.\n";
            state->lossRecovery = false;
            state->m_packetConservation = false;
            state->snd_cwnd = state->ssthresh;
            conn->emit(lossRecoverySignal, 0);
            if(tcp_state == CA_LOSS){
                bbr_exit_loss_recovery();
            }
            tcp_state = CA_OPEN;
            //bbr_exit_loss_recovery();
            //std::cout << "\n STATE: " << tcp_state << " at " << simTime() << endl;
        }
        else{
            if(dynamic_cast<TcpPacedConnection*>(conn)->doRetransmit()){
                bbr_note_loss();
            }
            conn->emit(lossRecoverySignal, state->snd_cwnd);
        }
    }

    bbr_main();
    sendData(false);

    conn->emit(maxBandwidthFilterSignal, bbr_max_bw());
    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void Bbr3Flavour::rttMeasurementComplete(simtime_t tSent, simtime_t tAcked)
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

    if(state->srtt == 0){
        state->srtt = newRTT;
    }

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

    state->m_lastRtt = newRTT;
    dynamic_cast<TcpPacedConnection*>(conn)->setMinRtt(std::min(newRTT, dynamic_cast<TcpPacedConnection*>(conn)->getMinRtt()));

    // record statistics
    EV_DETAIL << "Measured RTT=" << (newRTT * 1000) << "ms, updated SRTT=" << (srtt * 1000)
              << "ms, new RTO=" << (rto * 1000) << "ms\n";

    conn->emit(rttSignal, newRTT);
    conn->emit(srttSignal, srtt);
    conn->emit(rttvarSignal, rttvar);
    conn->emit(rtoSignal, rto);
    conn->emit(connMinRttSignal, dynamic_cast<BbrConnection*>(conn)->getMinRtt());
}

void Bbr3Flavour::receivedDuplicateAck()
{
    bool isHighRxtLost = dynamic_cast<TcpPacedConnection*>(conn)->checkIsLost(state->snd_una+state->snd_mss);
//    if(isHighRxtLost){
//        std::cout << "\n TRUE!! TEST WORKED" << endl;
//    }
    //bool isHighRxtLost = false;
    bool rackLoss = dynamic_cast<TcpPacedConnection*>(conn)->checkRackLoss();
    if ((rackLoss && !state->lossRecovery) || state->dupacks == state->dupthresh || (isHighRxtLost && !state->lossRecovery)) {
            EV_INFO << "Reno on dupAcks == DUPTHRESH(=" << state->dupthresh << ": perform Fast Retransmit, and enter Fast Recovery:";

            if (state->sack_enabled) {
                if ((state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) && !state->lossRecovery ) { // HighACK = snd_una
                    state->recoveryPoint = state->snd_max; // HighData = snd_max
                    bbr_save_cwnd();
                    //mark head as lost
                    dynamic_cast<TcpPacedConnection*>(conn)->setSackedHeadLost();
                    dynamic_cast<TcpPacedConnection*>(conn)->updateInFlight();
                    //bbr_save_cwnd();
                    EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
                    //state->snd_cwnd = state->ssthresh;
                    //state->snd_cwnd = dynamic_cast<BbrConnection*>(conn)->getBytesInFlight() + std::max(dynamic_cast<TcpPacedConnection*>(conn)->getLastAckedSackedBytes(), state->m_segmentSize);
                    //state->m_packetConservation = true;
                    state->lossRecovery = true;
//                    if(tcp_state == CA_LOSS){
//                        bbr_exit_loss_recovery();
//                    }
                    //bbr_exit_loss_recovery();
                    //bbr_exit_loss_recovery();
                    if(tcp_state != CA_LOSS){
                        tcp_state = CA_RECOVERY;
                    }


                    //std::cout << "\n STATE: " << tcp_state << " at " << simTime() << endl;
                    dynamic_cast<TcpPacedConnection*>(conn)->doRetransmit();
                    conn->emit(recoveryPointSignal, state->recoveryPoint);
                }
            }

            if (state->sack_enabled) {
                if (state->lossRecovery) {
                    EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                    restartRexmitTimer();
                }
            }
            EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
            conn->emit(highRxtSignal, state->highRxt);
    }
    else if(rackLoss){
        if (bbr_is_inflight_too_high()) {
            bbr_handle_inflight_too_high(false);
        }
    }

    bbr_main();
    sendData(false);
    //conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(pacingGainSignal, state->m_pacingGain);

    if(state->lossRecovery){
        conn->emit(lossRecoverySignal, state->snd_cwnd);
    }

}

void Bbr3Flavour::bbr_take_max_bw_sample(uint32_t bw)
{
    bw_hi[1] = std::max<uint32_t>(bw_hi[1], bw);
}

uint32_t Bbr3Flavour::bbr_max_bw()
{
    return std::max<uint32_t>(bw_hi[0], bw_hi[1]);
}

uint32_t Bbr3Flavour::bbr_update_round_start()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    uint32_t round_delivered = 0;
    state->m_roundStart = false;

    if (rs.m_interval > 0 &&
        rs.m_priorDelivered >= state->m_nextRoundDelivered) // equivalent to !before
    {
        state->m_nextRoundDelivered = state->m_delivered;
        state->m_roundCount++;
        state->m_roundStart = true;
        state->m_packetConservation = false;

        conn->emit(roundCountSignal, state->m_roundCount);
        conn->emit(nextRoundDeliveredSignal, state->m_nextRoundDelivered);
    }
    return round_delivered;
}

void Bbr3Flavour::bbr_calculate_bw_sample(bbr_context *ctx)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_interval == 0 || rs.m_delivered == 0 || rs.m_deliveryRate == 0) {
        return;
    }
    ctx->sample_bw = rs.m_deliveryRate;
}

void Bbr3Flavour::bbr_update_latest_delivery_signals(const struct bbr_context *ctx)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    state->m_lossRoundStart = false;
    if (rs.m_interval <= 0 || !rs.m_ackedSacked )
        return;

    m_bwLatest = std::max<uint32_t>(m_bwLatest, ctx->sample_bw);    ////// CHECK THIS
    state->m_inflightLatest = std::max<uint32_t>(state->m_inflightLatest, rs.m_delivered);
    if (rs.m_priorDelivered >= state->m_lossRoundDelivered) // equivalent to !before
    {
        state->m_lossRoundDelivered = state->m_delivered;
        state->m_lossRoundStart = true;
    }
}

void Bbr3Flavour::bbr_update_model(struct bbr_context *ctx)
{
    bbr_update_congestion_signals(ctx);
    bbr_update_ack_aggregation();
    bbr_check_loss_too_high_in_startup();
    bbr_check_full_bw_reached(ctx);
    bbr_check_drain();
    bbr_update_cycle_phase(ctx);
    bbr_update_min_rtt();
}

void Bbr3Flavour::bbr_update_congestion_signals(struct bbr_context *ctx)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_interval <= 0 || !rs.m_ackedSacked)
        return;

    uint32_t bw = ctx->sample_bw;

    if (!rs.m_isAppLimited || bw >= bbr_max_bw())
        bbr_take_max_bw_sample(bw);

    state->m_lossInRound |= (rs.m_bytesLoss > 0);

    if (!state->m_lossRoundStart)
        return;

    bbr_adapt_lower_bounds();

    state->m_lossInRound = 0;
}

void Bbr3Flavour::bbr_adapt_lower_bounds()
{
    if (bbr_is_probing_bandwidth())
        return;

    // LOSS RESPONSE
    if (state->m_lossInRound)
    {
        bbr_init_lower_bounds(true);
        bbr_loss_lower_bounds();
    }

    m_bwLo = std::max<uint32_t>(state->snd_mss, m_bwLo);
}

bool Bbr3Flavour::bbr_is_probing_bandwidth()
{
    return (m_state == BBR_STARTUP) || (m_state == BBR_PROBE_BW && (state->m_cycleIndex == BBR_BW_PROBE_REFILL || state->m_cycleIndex == BBR_BW_PROBE_UP));
}

void Bbr3Flavour::bbr_init_lower_bounds(bool init_bw)
{
    if (init_bw && m_bwLo == std::numeric_limits<uint32_t>::max ())
        m_bwLo = bbr_max_bw();
    if (m_inflightLo == std::numeric_limits<uint32_t>::max ())
        m_inflightLo = state->snd_cwnd;
}

void Bbr3Flavour::bbr_loss_lower_bounds()
{
    m_bwLo =  std::max<uint32_t>(m_bwLatest, (m_bwLo * 0.7));
    m_inflightLo = std::max<uint32_t>(state->m_inflightLatest, (m_inflightLo * 0.7));
}

void Bbr3Flavour::bbr_update_ack_aggregation()
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
    expectedAcked = bbr_bw() * epochProp;

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

void Bbr3Flavour::bbr_check_loss_too_high_in_startup()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (m_state != BbrMode_t::BBR_STARTUP)
      return;

    if (bbr_full_bw_reached())
        return;

    if (rs.m_bytesLoss > 0 && state->m_lossEventsInRound < 15)
        state->m_lossEventsInRound++;

    if (state->m_lossRoundStart
        && state->lossRecovery
        && state->m_lossEventsInRound >= state->bbr_full_loss_cnt
        && bbr_is_inflight_too_high()
    )
    {
        bbr_handle_queue_too_high_in_startup();
        return;
    }

    if(state->m_lossRoundStart)
        state->m_lossEventsInRound = 0;
}

bool Bbr3Flavour::bbr_is_inflight_too_high()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_bytesLoss > 0 && dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight() > 0)
    {
        //if (state->m_cycleIndex == BBR_BW_PROBE_UP)
        //    std::cout << "bytes lost " << rs.m_bytesLoss << " bytes in flight " << dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight() * 0.02;
        if (rs.m_bytesLoss > (dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight() * 0.02))
        {
            return true;
        }


    }
    return false;
}

void Bbr3Flavour::bbr_handle_queue_too_high_in_startup()
{
    state->m_fullBwReached = true;
    uint32_t bdp = bbr_inflight(bbr_max_bw(), 1);
    m_inflightHi = bdp;
}

uint32_t Bbr3Flavour::bbr_inflight(uint32_t bw, double gain)
{
    if (state->m_rtProp == SIMTIME_MAX)
    {
        return state->m_initialCWnd;
    }
    double quanta = 3 * state->m_sendQuantum;
    double estimatedBdp = bbr_bdp(bw, gain);
    conn->emit(estimatedBdpSignal, estimatedBdp);

    if (m_state == BbrMode_t::BBR_PROBE_BW && state->m_cycleIndex == 0)
    {
        return (estimatedBdp) + quanta + (2 * state->m_segmentSize);
    }
    return (estimatedBdp) + quanta;
}

uint32_t Bbr3Flavour::bbr_bdp(uint32_t bw, double gain)
{
    if (state->m_rtProp == SIMTIME_MAX)
        return state->m_initialCWnd;
    return ((bw * state->m_rtProp.dbl()) * gain);
}

void Bbr3Flavour::bbr_check_full_bw_reached(const struct bbr_context *ctx)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (state->m_fullBandwidthNow || rs.m_isAppLimited)
        return;
    /* Check if Bottleneck bandwidth is still growing*/
    if (ctx->sample_bw >= state->m_fullBandwidth * 1.25) // REPLACE CONSTANT WITH PARAMETER
    {
        bbr_reset_full_bw();
        state->m_fullBandwidth = ctx->sample_bw;
        return;
    }

    if (!state->m_roundStart)
        return;

    state->m_fullBandwidthCount++;
    state->m_fullBandwidthNow = state->m_fullBandwidthCount >= state->bbr_full_bw_cnt;
    state->m_fullBwReached |= state->m_fullBandwidthNow;
}

void Bbr3Flavour::bbr_check_drain()
{
    if (m_state == BBR_STARTUP && state->m_fullBwReached)
    {
        m_state = BBR_DRAIN;
        conn->emit(stateSignal, m_state);
        state->ssthresh = bbr_inflight(bbr_max_bw(), 1);
        bbr_reset_congestion_signals();

    }

    if (m_state == BBR_DRAIN && dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight() <= bbr_inflight(bbr_max_bw(), 1)){
        m_state = BBR_PROBE_BW;
        conn->emit(stateSignal, m_state);
        bbr_start_bw_probe_down();
    }
}

void Bbr3Flavour::bbr_update_cycle_phase(const struct bbr_context *ctx)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    bool is_bw_probe_done = false;
    uint32_t inflight;
    uint32_t bw;

    if (!bbr_full_bw_reached())
        return;

    if (bbr_adapt_upper_bounds())
         return;

    if (m_state != BbrMode_t::BBR_PROBE_BW)
        return;

    //inflight = tcb->m_bytesInFlight; //bbr_packets_in_net_at_edt(tcb, rs.m_priorDelivered); not implemented assuming rs.m_priorInFlight is adequate enough
    inflight = rs.m_priorInFlight;
    bw = bbr_max_bw();

    switch(state->m_cycleIndex)
    {
        case BBR_BW_PROBE_CRUISE:
            if (bbr_check_time_to_probe_bw())
                return;
            break;

        case BBR_BW_PROBE_REFILL:
            //COUT("BBR_BW_PROBE_REFILL at time " << NOW);
            if (state->m_roundStart)
            {
                state->m_bwProbeSamples = 1;
                bbr_start_bw_probe_up(ctx);
            }
            break;

        case BBR_BW_PROBE_UP:
            if (state->m_prevProbeTooHigh && inflight >= m_inflightHi) {
                state->m_stoppedRiskyProbe = true;
                is_bw_probe_done = true;
            } else {
                if (inflight >= bbr_inflight(bw, state->m_pacingGain))   {       //bbr_inflight(tcb, bw, m_pacingGain)) {
                    bbr_reset_full_bw();
                    state->m_fullBandwidth = ctx->sample_bw;
                    is_bw_probe_done = true;
                }
                else if (state->m_fullBandwidthNow) {
                    is_bw_probe_done = true;
                }
            }
            if (is_bw_probe_done)
            {
                state->m_prevProbeTooHigh = false;
                bbr_start_bw_probe_down();
            }
            break;
        case BBR_BW_PROBE_DOWN:
            if (bbr_check_time_to_probe_bw())
                return;     /* already decided state transition */
            if (bbr_check_time_to_cruise(bw))
                bbr_start_bw_probe_cruise();
            break;
        default:
            break;
    }
}

bool Bbr3Flavour::bbr_full_bw_reached()
{
    return state->m_fullBwReached;
}

bool Bbr3Flavour::bbr_adapt_upper_bounds()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (m_ackPhase == BbrAckPhase_t::BBR_ACKS_PROBE_STARTING && state->m_roundStart)
        m_ackPhase = BbrAckPhase_t::BBR_ACKS_PROBE_FEEDBACK;
    if (m_ackPhase == BbrAckPhase_t::BBR_ACKS_PROBE_STOPPING && state->m_roundStart)
    {
        state->m_bwProbeSamples = 0;
        m_ackPhase = BbrAckPhase_t::BBR_ACKS_INIT;
        if (m_state == BbrMode_t::BBR_PROBE_BW && !rs.m_isAppLimited)
            bbr_advance_max_bw_filter();

        if (m_state == BbrMode_t::BBR_PROBE_BW && state->m_stoppedRiskyProbe && !state->m_prevProbeTooHigh)
        {
            bbr_start_bw_probe_refill(0);
            return true;
        }
    }

    if (bbr_is_inflight_too_high())
    {
        if (state->m_bwProbeSamples)
                bbr_handle_inflight_too_high(false);
    }
    else {
        if (m_inflightHi == std::numeric_limits<uint32_t>::max ())
            return false;
        if (dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight() > m_inflightHi)
            m_inflightHi = dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight();

        if (m_state == BBR_PROBE_BW && state->m_cycleIndex == BBR_BW_PROBE_UP)
            bbr_probe_inflight_hi_upward();
    }
    return false;
}

bool Bbr3Flavour::bbr_check_time_to_probe_bw()
{
    if (bbr_has_elapsed_in_phase(state->m_probeWaitTime) || bbr_is_reno_coexistence_probe_time())
    {
        bbr_start_bw_probe_refill(0);
        return true;
    }
    return false;
}

void Bbr3Flavour::bbr_start_bw_probe_refill(uint32_t bw_probe_up_rounds)
{
    bbr_reset_lower_bounds();
    state->m_bwProbeUpRounds = bw_probe_up_rounds;
    state->m_bwProbeUpAcks = 0;
    state->m_stoppedRiskyProbe = 0;
    state->m_cycleStamp = simTime();
    m_ackPhase = BbrAckPhase_t::BBR_ACKS_REFILLING;
    state->m_nextRoundDelivered = state->m_delivered;
    bbr_set_cycle_idx(BBR_BW_PROBE_REFILL);
}

void Bbr3Flavour::bbr_reset_lower_bounds()
{
    m_bwLo = std::numeric_limits<uint32_t>::max();
    m_inflightLo = std::numeric_limits<uint32_t>::max();
}

void Bbr3Flavour::bbr_set_cycle_idx(uint32_t cycle_idx)
{
    state->m_cycleIndex = cycle_idx;
    state->m_tryFastPath = false;
}

void Bbr3Flavour::bbr_handle_inflight_too_high(bool rsmode)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    state->m_prevProbeTooHigh = true;
    state->m_bwProbeSamples = 0;
    if (rsmode && !rs.m_isAppLimited)
    {
        m_inflightHi = std::max(rs.m_priorInFlight, static_cast<uint32_t>(bbr_target_inflight() * (1 - state->bbr_beta)));
        goto done2;

    }
    if (!rs.m_isAppLimited)
        m_inflightHi = (bbr_target_inflight() * (1 - state->bbr_beta));
    done2:
    if (m_state == BbrMode_t::BBR_PROBE_BW && state->m_cycleIndex == BBR_BW_PROBE_UP)
    {
        bbr_start_bw_probe_down();
    }
}

uint32_t Bbr3Flavour::bbr_target_inflight()
{
    uint32_t bdp = bbr_inflight(bbr_bw(), 1);   //REPLACE WITH BBR VERSION LATER
    return std::min(bdp, state->snd_cwnd);
}

void Bbr3Flavour::bbr_start_bw_probe_down()
{
    bbr_reset_congestion_signals();
    state->m_bwProbeUpCount = std::numeric_limits<uint32_t>::max();
    bbr_pick_probe_wait();
    state->m_cycleStamp = simTime();
    m_ackPhase = BbrAckPhase_t::BBR_ACKS_PROBE_STOPPING;
    state->m_nextRoundDelivered = state->m_delivered;
    bbr_set_cycle_idx(BBR_BW_PROBE_DOWN);
    //std::cout << "\n PROBING DOWN AT " << simTime() << endl;
}

void Bbr3Flavour::bbr_update_min_rtt()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    bool probe_rtt_expired = simTime() > (state->m_probeRttMinStamp + state->bbr_probe_rtt_win);
    if (state->m_lastRtt >= 0 && (state->m_lastRtt < state->m_probeRttMin || (probe_rtt_expired /* && rs.is ack delayed*/ ))) // rs in ns3 does not store min rtt anywhere but the tcb object does
    {
        state->m_probeRttMin = state->m_lastRtt;
        state->m_probeRttMinStamp = simTime();
    }

    bool min_rtt_expired = simTime() > (state->m_rtPropStamp + state->bbr_min_rtt_win_sec); // some confustion around this
    if (state->m_probeRttMin <= state->m_rtProp || min_rtt_expired)
    {
        state->m_rtProp = state->m_probeRttMin;
        state->m_rtPropStamp = state->m_probeRttMinStamp;
        //std::cout << "\n " << state->m_rtPropStamp << endl;
        conn->emit(minRttSignal, state->m_rtProp);
    }


    if (probe_rtt_expired && !state->m_idleRestart  && m_state != BbrMode_t::BBR_PROBE_RTT)
    {
        m_state = BbrMode_t::BBR_PROBE_RTT;
        bbr_save_cwnd();
        state->m_probeRttDoneStamp = 0;
        m_ackPhase = BbrAckPhase_t::BBR_ACKS_PROBE_STOPPING;
        state->m_nextRoundDelivered = state->m_delivered;
    }

    if (m_state == BbrMode_t::BBR_PROBE_RTT)
    {
        state->m_appLimited = (state->m_delivered + dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight()) < 0 ;
        if (state->m_probeRttDoneStamp == 0 && dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight() <= bbr_probe_rtt_cwnd())
        {
            state->m_probeRttDoneStamp = simTime() + state->bbr_probe_rtt_mode_ms;
            state->m_probeRttRoundDone = false;
            state->m_nextRoundDelivered = state->m_delivered;
        }
        else if (state->m_probeRttDoneStamp != 0)
        {
            if (state->m_roundStart)
                state->m_probeRttRoundDone = true;
            if (state->m_probeRttRoundDone )
                bbr_check_probe_rtt_done();
        }
    }

    if (rs.m_delivered > 0)
        state->m_idleRestart = false;



    if (rs.m_delivered > 0)
        state->m_idleRestart = false;
}

void Bbr3Flavour::bbr_check_probe_rtt_done()
{
    if(!(state->m_probeRttDoneStamp != 0 && simTime() > state->m_probeRttDoneStamp))
        return;

    state->m_probeRttMinStamp = simTime();
    state->snd_cwnd = std::max(state->m_priorCwnd, state->snd_cwnd); // prioe restore cwnd
    bbr_exit_probe_rtt();
}

void Bbr3Flavour::bbr_exit_probe_rtt()
{
    bbr_reset_lower_bounds();
    if (bbr_full_bw_reached()){
        m_state = BbrMode_t::BBR_PROBE_BW;
        conn->emit(stateSignal, m_state);
        bbr_start_bw_probe_down();
        bbr_start_bw_probe_cruise();
    } else {
        m_state = BbrMode_t::BBR_STARTUP;
        conn->emit(stateSignal, m_state);
    }
}

void Bbr3Flavour::initRoundCounting()
{
    state->m_nextRoundDelivered = 0;
    state->m_roundStart = false;
    state->m_roundCount = 0;
}

void Bbr3Flavour::initFullPipe()
{
    state->m_fullBwReached = false;
    state->m_fullBandwidth = 0;
    state->m_fullBandwidthCount = 0;
}

void Bbr3Flavour::initPacingRate()
{
    simtime_t rtt;
    simtime_t connMinRtt = dynamic_cast<BbrConnection*>(conn)->getMinRtt();
    if (connMinRtt != SIMTIME_MAX)
    {
        if (connMinRtt < 0.001){
            rtt = 0.001;
        }
        else{
            rtt = connMinRtt;
        }
        state->m_hasSeenRtt = true;
    }
    else
    {
        rtt = SimTime(0.001);
    }

    uint32_t nominalBandwidth = (state->snd_cwnd / rtt.dbl()); //* 8 / rtt.dbl());
    if((state->m_pacingGain * (double) nominalBandwidth) > 0){
        double pace = 1/((state->m_pacingGain *(double)nominalBandwidth)/(double)state->m_segmentSize);
        dynamic_cast<BbrConnection*>(conn)->changeIntersendingTime(pace);
    }
    bbr_take_max_bw_sample(nominalBandwidth);
}

void Bbr3Flavour::bbr_save_cwnd()
{
    if (!state->lossRecovery && m_state != BbrMode_t::BBR_PROBE_RTT)
        state->m_priorCwnd = state->snd_cwnd;
    else
        state->m_priorCwnd = std::max(state->m_priorCwnd, state->snd_cwnd);
    conn->emit(priorCwndSignal, state->m_priorCwnd);
}

void Bbr3Flavour::restoreCwnd()
{
    state->snd_cwnd = std::max(state->m_priorCwnd, state->snd_cwnd);
    conn->emit(restoreCwndSignal, state->snd_cwnd);
}

void Bbr3Flavour::bbr_reset_full_bw()
{
    state->m_fullBandwidth = 0;
    state->m_fullBandwidthCount = 0;
    state->m_fullBandwidthNow = false;
}

uint32_t Bbr3Flavour::bbr_probe_rtt_cwnd()
{
    return std::max<uint32_t>(state->m_minPipeCwnd, bbr_bdp(bbr_bw(), 0.5)); // convert to constant later
}

void Bbr3Flavour::bbr_start_bw_probe_up(const struct bbr_context* ctx)
{
    m_ackPhase = BBR_ACKS_PROBE_STARTING;
    state->m_nextRoundDelivered = state->m_delivered;
    state->m_cycleStamp = simTime();
    bbr_reset_full_bw();
    state->m_fullBandwidth = ctx->sample_bw;
    bbr_set_cycle_idx(BBR_BW_PROBE_UP);
    bbr_raise_inflight_hi_slope();
}

bool Bbr3Flavour::bbr_check_time_to_cruise(uint32_t bw)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (rs.m_priorInFlight > bbr_inflight_with_headroom())
        return false;
    return rs.m_priorInFlight <= bbr_inflight(bw, 1);
}

bool Bbr3Flavour::bbr_has_elapsed_in_phase(simtime_t interval)
{
    return (simTime() - (state->m_cycleStamp + interval)) > 0;
}

void Bbr3Flavour::bbr_advance_max_bw_filter()
{
    if(bw_hi[1] == 0)
        return;
    bw_hi[0] = bw_hi[1];
    bw_hi[1] = 0;
}

void Bbr3Flavour::bbr_start_bw_probe_cruise()
{
    state->m_cycleStamp = simTime();
    if (m_inflightLo != std::numeric_limits<uint32_t>::max())
        m_inflightLo = std::min(m_inflightLo, m_inflightHi);
    bbr_set_cycle_idx(BBR_BW_PROBE_CRUISE);
}

void Bbr3Flavour::bbr_pick_probe_wait()
{
    boost::random::uniform_int_distribution<> dist(0, 2);
    state->m_roundsSinceProbe = (uint)dist(gen);
    boost::random::uniform_int_distribution<> dist2(0, 1000);
    state->m_probeWaitTime = 2 + (dist2(gen))/1000;
}

uint32_t Bbr3Flavour::bbr_inflight_with_headroom()
{
    if (m_inflightHi == std::numeric_limits<uint32_t>::max ())
        return std::numeric_limits<uint32_t>::max ();

    uint32_t headroom = (m_inflightHi * state->bbr_inflight_headroom) ;
    headroom = std::max<uint32_t>(headroom, 1);

    return std::max<uint32_t>(m_inflightHi - headroom, state->m_minPipeCwnd);
}

void Bbr3Flavour::bbr_raise_inflight_hi_slope()
{
    uint32_t growth_this_round = 1 << state->m_bwProbeUpRounds;
    state->m_bwProbeUpRounds = std::min<uint32_t>(state->m_bwProbeUpRounds + 1, 30);
    state->m_bwProbeUpCount = std::max<uint32_t> (state->snd_cwnd / growth_this_round, 1);
}

void Bbr3Flavour::bbr_probe_inflight_hi_upward()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (state->snd_cwnd < m_inflightHi)
    {
        state->m_bwProbeUpAcks = 0;
        return;
    }

    state->m_bwProbeUpAcks += rs.m_ackedSacked;
    if (state->m_bwProbeUpAcks >= state->m_bwProbeUpCount)
    {
       uint32_t delta = state->m_bwProbeUpAcks / state->m_bwProbeUpCount;
       state->m_bwProbeUpAcks -= delta * state->m_bwProbeUpCount;
       m_inflightHi += delta * state->m_segmentSize;
       state->m_tryFastPath = false;
    }

    if (state->m_roundStart)
        bbr_raise_inflight_hi_slope();
}

void Bbr3Flavour::bbr_reset_congestion_signals()
{
    state->m_lossInRound = false;
    state->m_ecnInRound = false;
    //m_lossInCycle = false;
    state->m_ecn_in_cycle = false;
    m_bwLatest = 0;
    state->m_inflightLatest = 0;
}

bool Bbr3Flavour::bbr_is_reno_coexistence_probe_time()
{
    int32_t rounds = std::min<int32_t>(state->bbr_bw_probe_max_rounds, bbr_target_inflight());
    return state->m_roundsSinceProbe >= rounds;
}

uint32_t Bbr3Flavour::bbr_bw()
{
    return std::min<uint32_t>(bbr_max_bw(), m_bwLo);
}

void Bbr3Flavour::setSendQuantum()
{
    state->m_sendQuantum = 1 * state->m_segmentSize;
}

void Bbr3Flavour::bbr_set_cwnd()
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    updateTargetCwnd();

    if (!rs.m_ackedSacked)
    {
        goto done;
    }

//    if (state->lossRecovery)
//    {
//        if (modulateCwndForRecovery())
//        {
//            goto done;
//        }
//    }

    if (!state->m_packetConservation){
        if (state->m_fullBwReached)
        {
            state->snd_cwnd = std::min(state->snd_cwnd + (uint32_t)rs.m_ackedSacked, state->m_targetCWnd);
        }
        else if (state->snd_cwnd < state->m_targetCWnd || state->m_delivered < state->m_initialCWnd)
        {
            state->snd_cwnd  = state->snd_cwnd  + rs.m_ackedSacked;
        }
        state->snd_cwnd  = std::max(state->snd_cwnd , state->m_minPipeCwnd);
    }
done:
    if (m_state == BbrMode_t::BBR_PROBE_RTT)
        state->snd_cwnd  = std::min(state->snd_cwnd, bbr_probe_rtt_cwnd());
}

void Bbr3Flavour::bbr_update_gains()
{
    switch (m_state) {
        case BBR_STARTUP:
            state->m_pacingGain = 2.89;
            state->m_cWndGain   = 2.89;
            conn->emit(pacingGainSignal, state->m_pacingGain);
            break;
        case BBR_DRAIN:
            state->m_pacingGain = 1.0 * 1000.0 / 2885.0;  /* slow, to drain */
            state->m_cWndGain   = 2;  /* keep cwnd */
            conn->emit(pacingGainSignal, state->m_pacingGain);
            break;
        case BBR_PROBE_BW:
            state->m_pacingGain = PACING_GAIN_CYCLE[state->m_cycleIndex];
            state->m_cWndGain   = 2;
            if (state->bbr_bw_probe_cwnd_gain !=0  && state->m_cycleIndex == BBR_BW_PROBE_UP)
                state->m_cWndGain += 1 * state->bbr_bw_probe_cwnd_gain / 4;
            conn->emit(pacingGainSignal, state->m_pacingGain);
            break;
        case BBR_PROBE_RTT:
            state->m_pacingGain = 1;
            state->m_cWndGain   = 1;
            conn->emit(pacingGainSignal, state->m_pacingGain);
            break;
        default:
            break;
    }
}

void Bbr3Flavour::bbr_set_pacing_rate(double gain)
{
    uint32_t rate = (double) gain * (double) bbr_bw();
    rate *= ((double)1 - state->m_pacingMargin);
    uint32_t maxRate = 500000000; // 4Gbps
    rate = std::min(rate, maxRate);

    if (!state->m_hasSeenRtt && dynamic_cast<BbrConnection*>(conn)->getMinRtt() != SIMTIME_MAX)
    {
        initPacingRate();
    }

    //double pace = state->m_minRtt.dbl()/(((double)rate*state->m_lastRtt.dbl())/(double)state->m_segmentSize);
    double pace = (double)1/(((double)rate)/(double)state->m_segmentSize);
    if ((state->m_fullBwReached || pace < dynamic_cast<BbrConnection*>(conn)->getPacingRate().dbl()) && rate > 0)
    {
        dynamic_cast<BbrConnection*>(conn)->changeIntersendingTime(pace);
    }
}

void Bbr3Flavour::updateTargetCwnd()
{
    state->m_targetCWnd = bbr_inflight(bbr_bw(), state->m_cWndGain) + ackAggregationCwnd();
}

bool Bbr3Flavour::modulateCwndForRecovery()
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

void Bbr3Flavour::bbr_bound_cwnd_for_inflight_model()
{
    if (!state->m_isInitialized)
        return;
    uint32_t cap = std::numeric_limits<uint32_t>::max();
    if (m_state == BBR_PROBE_BW && state->m_cycleIndex  != BBR_BW_PROBE_CRUISE)
    {
        cap = m_inflightHi;
    } else {
        if (m_state == BBR_PROBE_RTT  || ( m_state == BBR_PROBE_BW && state->m_cycleIndex  == BBR_BW_PROBE_CRUISE)){
            cap = bbr_inflight_with_headroom();
        }
    }
    cap = std::min(cap, m_inflightLo);
    cap = std::max(cap, state->m_minPipeCwnd);
    state->snd_cwnd = std::min(state->snd_cwnd, cap);
}

void Bbr3Flavour::bbr_advance_latest_delivery_signals(struct bbr_context *ctx)
{
    BbrConnection::RateSample rs = dynamic_cast<BbrConnection*>(conn)->getRateSample();
    if (state->m_lossRoundStart) {
        m_bwLatest = ctx->sample_bw;
        state->m_inflightLatest = rs.m_delivered;
    }
}

uint32_t Bbr3Flavour::ackAggregationCwnd()
{
    uint32_t maxAggrBytes; // MaxBW * 0.1 secs
    uint32_t aggrCwndBytes = 0;

    if (state->m_extraAckedGain && state->m_fullBwReached)
    {
        maxAggrBytes = bbr_bw() * 0.1;
        aggrCwndBytes = state->m_extraAckedGain * std::max(m_extraAcked[0], m_extraAcked[1]);
        aggrCwndBytes = std::min(aggrCwndBytes, maxAggrBytes);
    }
    return aggrCwndBytes;
}

void Bbr3Flavour::bbr_exit_loss_recovery()
{
    state->snd_cwnd = std::max(state->snd_cwnd, state->m_priorCwnd);
    //state->m_packetConservation = true;
    state->m_tryFastPath = 0;
}

void Bbr3Flavour::bbr_note_loss()
{
    if (!state->m_lossInRound)  /* first loss in this round trip? */
        state->m_lossRoundDelivered = dynamic_cast<TcpPacedConnection*>(conn)->getDelivered();  /* set round trip */
    state->m_lossInRound = true;
    state->m_lossInCycle = true;
}

void Bbr3Flavour::notifyLost()
{
    bbr_note_loss();
    if (bbr_is_inflight_too_high()) {
        bbr_handle_inflight_too_high(false);
    }

}

} // namespace tcp
} // namespace inet
