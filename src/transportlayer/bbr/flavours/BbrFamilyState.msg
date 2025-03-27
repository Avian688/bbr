//
// Copyright (C) 2013 Maria Fernandez, Carlos Calafate, Juan-Carlos Cano and Pietro Manzoni
// Copyright (C) 2022 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

import inet.common.INETDefs;
import inet.transportlayer.tcp.flavours.TcpTahoeRenoFamilyState;

namespace inet::tcp;
///
/// State variables for BBR.
///
struct BbrFamilyStateVariables extends TcpTahoeRenoFamilyStateVariables
{
    @descriptor(readonly);
    
    double R; //pacing rate
    
    int rttCount = 0;
    
    double firstSentTime = 0; //used for send elapsed
    double deliveredTime = 0; //used for ack elapsed
    long m_delivered = 0;
    uint32_t m_appLimited = 0;
    uint32_t m_txItemDelivered = 0;
    bool isAppLimited = false;
    bool m_fullBwReached =false;
    uint32_t m_bandwidthWindowLength = 10;
    uint32_t m_bwProbeUpRounds = 0;
    
    simtime_t m_lastRtt = 0;
    
    uint32 m_nextRoundDelivered = 0;
    uint32 m_roundCount = 0;
    bool m_roundStart = false;
    bool m_packetConservation = false;
    
    simtime_t m_cycleStamp = 0;
    uint32_t m_cycleIndex = 0;
    bool m_minRttExpired = false;
    
    double m_pacingGain = 0;
    double m_cWndGain = 0;
    double m_highGain = 2.89; //Constant
    
    simtime_t m_minRtt = SIMTIME_MAX;
    simtime_t m_minRttStamp = 0;
    simtime_t m_minRttFilterLen = SimTime(10);
    
    simtime_t m_rtProp = SIMTIME_MAX;
    simtime_t m_probeRttMin = SIMTIME_MAX;
    simtime_t m_probeRttMinStamp = 0;
    simtime_t m_rtPropStamp = 0;
    
    uint32_t m_sendQuantum = 0;
    
    bool m_isPipeFilled = false;
    
    uint32_t m_fullBandwidth = 0;
    uint32_t m_fullBandwidthCount = 0;
    
    bool m_idleRestart = false;
    
    simtime_t m_probeRttDuration = SimTime(0.2);
    
    simtime_t m_probeRttDoneStamp = 0;
    bool m_probeRttRoundDone = false;
    
    uint32_t m_minPipeCwnd = 0;
    
    uint32_t m_priorCwnd = 0;
    
    bool m_hasSeenRtt = false;
    double m_pacingMargin = 0.01; 
    
    uint32_t m_initialCWnd = 0;
    
    uint32_t m_targetCWnd = 0;
    
    bool m_isInitialized = false;
    
    uint32_t m_extraAckedGain = 1;
    uint32_t m_extraAckedWinRtt = 0;
    uint32_t m_extraAckedWinRttLength = 5;
    uint32_t m_extraAckedIdx = 0;
    simtime_t m_ackEpochTime = 0;
    uint32_t m_ackEpochAckedResetThresh = 1 << 12;
    uint32_t m_ackEpochAcked = 0;
    
    uint32_t m_segmentSize = 1448;
    
    uint32_t prevMaxBandwidth = 0;
    
    // BBR v3 States
    
    bool m_tryFastPath = false; //!< Try to use fast path
    bool m_fullBandwidthNow = false;     //!< Recently reached full bw plateau? 
    uint32_t m_startupEcnRounds = 0;     //!< Consecutive high ECN STARTUP rounds
    bool m_lossInCycle = false;        //!< Packet loss in this cycle?
    bool m_ecn_in_cycle = false;       //!< ECN in this cycle?
    uint32_t m_lossRoundDelivered = 0;   //!< Delivered packets at the end of loss round
	uint32_t m_undoBwLo = 0;             //!< bw_lo before latest losses
    uint32_t m_undoInflightLo = 0;       //!< inflight_lo before latest losses
    uint32_t m_undoInflightHi = 0;       //!< inflight_hi before latest losses
    uint32_t m_inflightLatest = 0;
    
    uint32_t m_bwProbeUpCount = 0;   //!< Packets delivered per inflight_hi incr
	uint32_t m_bwProbeUpAcks = 0;    //!< Packets (S)ACKed since inflight_hi incr
    simtime_t m_probeWaitTime =0;   //!< PROBE_DOWN until next clock-driven probe
    bool m_ecnEligible = false;           //!< Sender can use ECN (RTT, handshake)?
    uint32_t m_bwProbeSamples = 0;       //!< Rate samples reflect bw probing?
	bool m_prevProbeTooHigh = false;     //!< Did last PROBE_UP go too high?
	bool m_stoppedRiskyProbe = false;    //!< Last PROBE_UP stopped due to risk?
    uint32_t m_roundsSinceProbe = 0; //!< Packet-timed rounds since probed bw
    bool m_lossRoundStart = 1;       //!< Loss round delivered round trip?
    bool m_lossInRound = 1;       //!< Loss marked in this round trip?
    bool m_ecnInRound = false;       //!< ECN marked in this round trip?
    uint32_t m_lossEventsInRound = 0; //!< Losses in STARTUP round

    uint32_t bw_probe_up_rounds = 5;
    
    
    const simtime_t bbr_min_rtt_win_sec = 10;

    const simtime_t bbr_probe_rtt_win  = 5;

    const uint32_t bbr_bw_probe_max_rounds = 63;

    const double bbr_ecn_reprobe_gain = 1 / 2;

    const double bbr_loss_thresh = 2/100;

    const double bbr_ecn_thresh = 0.5;

    const double bbr_beta = (1 * 30 / 100);

    const double bbr_inflight_headroom = 15 / 100;

    const uint32_t bbr_full_loss_cnt = 6;

    const double bbr_full_bw_thresh = 1 * 5 / 4;

    const uint32_t bbr_full_bw_cnt = 3;

    const double bbr_startup_pacing_gain = 1 * 277 / 100 + 1;

    const uint32_t bbr_startup_cwnd_gain = 2;

    const double bbr_drain_gain = 1 * 1000 / 2885;

    const uint32_t bbr_bw_probe_cwnd_gain = 1;

    const uint32_t bbr_cwnd_gain  = 2;

    const simtime_t bbr_probe_rtt_mode_ms = 0.2;

    bool startedAfter = false;
    uint32_t maxBw = 0;
    uint32_t wildcard = 0;
};

cplusplus(BbrFamilyStateVariables) {{
  public:
    virtual std::string str() const override;
    virtual std::string detailedInfo() const override;
}}

