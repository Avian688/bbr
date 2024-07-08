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

#ifndef TRANSPORTLAYER_BBR_FLAVOURS_BBRFLAVOUR_H_
#define TRANSPORTLAYER_BBR_FLAVOURS_BBRFLAVOUR_H_

#include <random>
#include "../BbrConnection.h"
#include "BbrFamily.h"
#include "windowedfilter.h"

namespace inet {
namespace tcp {

/**
 * State variables for Bbr.
 */
typedef BbrFamilyStateVariables BbrStateVariables;

/**
 * Implements Bbr.
 */
class BbrFlavour : public BbrFamily
{
  public:

    static const uint8_t GAIN_CYCLE_LENGTH = 8;

    const static double PACING_GAIN_CYCLE[];

    enum BbrMode_t
    {
        BBR_STARTUP,   /**< Ramp up sending rate rapidly to fill pipe */
        BBR_DRAIN,     /**< Drain any queue created during startup */
        BBR_PROBE_BW,  /**< Discover, share bw: pace around estimated bw */
        BBR_PROBE_RTT, /**< Cut inflight to min to probe min_rtt */
    };

    typedef WindowedFilter<uint32_t,
                               MaxFilter<uint32_t>,
                               uint32_t,
                               uint32_t>
            MaxBandwidthFilter_t;

  protected:
    BbrStateVariables *& state;
    static simsignal_t additiveIncreaseSignal;
    static simsignal_t minRttSignal;
    static simsignal_t maxBandwidthFilterSignal;
    static simsignal_t stateSignal;
    static simsignal_t pacingGainSignal;
    static simsignal_t targetCwndSignal;

    simtime_t rtt;
    std::default_random_engine generator;
    uint32_t m_extraAcked[2] = {0, 0};

    BbrMode_t m_state{BbrMode_t::BBR_STARTUP};
    MaxBandwidthFilter_t m_maxBwFilter;

    bool initPackets;
    /** Create and return a OrbtcpStateVariables object. */
    virtual TcpStateVariables *createStateVariables() override
    {
        return new BbrStateVariables();
    }

    virtual void initialize() override;

    /** Utility function to recalculate ssthresh */
    virtual void recalculateSlowStartThreshold();

    /** Redefine what should happen on retransmission */
    virtual void processRexmitTimer(TcpEventCode& event) override;

    virtual void rttMeasurementComplete(simtime_t tSent, simtime_t tAcked) override;

    virtual void updateModelAndState();

    virtual void updateControlParameters();

    virtual void updateBottleneckBandwidth();

    virtual void updateAckAggregation();

    virtual void checkCyclePhase();

    virtual void checkFullPipe();

    virtual void checkDrain();

    virtual void updateRTprop();

    virtual void checkProbeRTT();

    virtual void updateRound();

    virtual bool isNextCyclePhase();

    virtual void advanceCyclePhase();

    virtual uint32_t inFlight(double gain);

    virtual void enterDrain();

    virtual void enterProbeBW();

    virtual void setBbrState(BbrMode_t mode);

    virtual void enterProbeRTT();

    virtual void handleProbeRTT();

    virtual void saveCwnd();

    virtual void restoreCwnd();

    virtual void exitProbeRTT();

    virtual void enterStartup();

    virtual void setPacingRate(double gain);

    virtual void setSendQuantum();

    virtual void setCwnd();

    virtual void initPacingRate();

    virtual bool modulateCwndForRecovery();

    virtual void updateTargetCwnd();

    virtual uint32_t ackAggregationCwnd();

    virtual void modulateCwndForProbeRTT();

    virtual void initRoundCounting();

    virtual void initFullPipe();

  public:
    /** Constructor */
    BbrFlavour();

    virtual void established(bool active) override;

    virtual void receivedDataAck(uint32_t firstSeqAcked, const Ptr<const SkbInfo> skbInfo) override;

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck() override;

    virtual void setFirstSentTime(simtime_t time) { state->firstSentTime = time.dbl();};
    virtual void setDeliveredTime(simtime_t time) { state->deliveredTime = time.dbl();};

    virtual double getFirstSentTime() { return state->firstSentTime;};
    virtual double getDeliveredTime() { return state->deliveredTime;};

    };

} // namespace tcp
} // namespace inet

#endif

