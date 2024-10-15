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
/// State variables for OrbTCP.
///
struct BbrFamilyStateVariables extends TcpTahoeRenoFamilyStateVariables
{
    @descriptor(readonly);
    
    
    uint32_t lastUpdateSeq;
    
    double R; //pacing rate
    
    int rttCount = 0;
    
    double firstSentTime; //used for send elapsed
    double deliveredTime; //used for ack elapsed
    long m_delivered;
    bool isAppLimited;
    
    uint32_t m_bandwidthWindowLength = 10;
    
    simtime_t connMinRtt = SIMTIME_MAX;
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
    
    uint32_t m_sendQuantum = 0;
    
    bool m_isPipeFilled = false;
    
    uint32_t m_fullBandwidth = 0;
    uint32_t m_fullBandwidthCount = 0;
    
    bool m_idleRestart = false;
    
    simtime_t m_probeRttDuration = SimTime(0.2);
    
    simtime_t m_probeRttDoneStamp = 0;
    bool m_probeRttRoundDone = false;
    
    bool m_appLimited = false;
    
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
    
    uint32_t m_segmentSize;
    
    uint32_t prevMaxBandwidth;
};

cplusplus(BbrFamilyStateVariables) {{
  public:
    virtual std::string str() const override;
    virtual std::string detailedInfo() const override;
}}

