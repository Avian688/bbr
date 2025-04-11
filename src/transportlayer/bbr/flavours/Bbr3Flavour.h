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

#ifndef TRANSPORTLAYER_BBR_FLAVOURS_BBR3FLAVOUR_H_
#define TRANSPORTLAYER_BBR_FLAVOURS_BBR3FLAVOUR_H_

#include <random>
#include "../BbrConnection.h"
#include "BbrFamily.h"
#include "windowedfilter.h"
#include "BbrFamilyState_m.h"
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random.hpp>
namespace inet {
namespace tcp {

/**
 * State variables for Bbr.
 */
typedef BbrFamilyStateVariables BbrStateVariables;

/**
 * Implements Bbr.
 */
class Bbr3Flavour : public BbrFamily
{
  public:
    struct bbr_context {
        uint32_t sample_bw;
    };

    const static double PACING_GAIN_CYCLE[];

    enum BbrMode_t
    {
        BBR_STARTUP,   /**< Ramp up sending rate rapidly to fill pipe */
        BBR_DRAIN,     /**< Drain any queue created during startup */
        BBR_PROBE_BW,  /**< Discover, share bw: pace around estimated bw */
        BBR_PROBE_RTT, /**< Cut inflight to min to probe min_rtt */
    };

    enum BbrPacingGainPhase_t
    {
       BBR_BW_PROBE_UP,  /* push up inflight to probe for bw/vol */
       BBR_BW_PROBE_DOWN,  /* drain excess inflight from the queue */
       BBR_BW_PROBE_CRUISE,  /* use pipe, w/ headroom in queue/pipe */
       BBR_BW_PROBE_REFILL,  /* v2: refill the pipe again to 100% */
    };

    enum BbrAckPhase_t
    {
       BBR_ACKS_INIT,        /* not probing; not getting probe feedback */
       BBR_ACKS_REFILLING,   /* sending at est. bw to fill pipe */
       BBR_ACKS_PROBE_STARTING,  /* inflight rising to probe bw */
       BBR_ACKS_PROBE_FEEDBACK,  /* getting feedback from bw probing */
       BBR_ACKS_PROBE_STOPPING,  /* stopped probing; still getting feedback */
    };

    enum BbrState
    {
        CA_OPEN,
        CA_LOSS,
        CA_RECOVERY,
    };
    /**
     * \brief Literal names of BBR mode for use in log messages
     */
    static const char* const BbrModeName[BBR_PROBE_RTT + 1];

    /**
    * \brief Literal names of cycle modes for use in log messages
    */
    static const char* const BbrCycleName[BBR_PROBE_RTT + 1];

    void bbr_update_gains();

  protected:
    BbrStateVariables *& state;
    static simsignal_t additiveIncreaseSignal;
    static simsignal_t minRttSignal;
    static simsignal_t maxBandwidthFilterSignal;
    static simsignal_t stateSignal;
    static simsignal_t pacingGainSignal;
    static simsignal_t targetCwndSignal;
    static simsignal_t estimatedBdpSignal;
    static simsignal_t priorCwndSignal;
    static simsignal_t roundCountSignal;

    static simsignal_t recoverSignal;
    static simsignal_t lossRecoverySignal;
    static simsignal_t highRxtSignal;
    static simsignal_t recoveryPointSignal;
    static simsignal_t connMinRttSignal;
    static simsignal_t nextRoundDeliveredSignal;
    static simsignal_t restoreCwndSignal;

    simtime_t rtt;
    boost::random::mt19937 gen;
    uint32_t m_extraAcked[2]{0, 0};
    uint32_t bw_hi[2]{0, 0};

    BbrMode_t m_state{BbrMode_t::BBR_STARTUP};
    BbrAckPhase_t m_ackPhase = BbrAckPhase_t::BBR_ACKS_PROBE_FEEDBACK; //!< BBR ack phase
    BbrState tcp_state = BbrState::CA_OPEN;

    uint32_t m_bwLatest = std::numeric_limits<uint32_t>::max ();         //!< Maximum delivered bandwidth in last round trip
    uint32_t m_bwLo = std::numeric_limits<uint32_t>::max ();
    uint32_t m_inflightLo = std::numeric_limits<uint32_t>::max ();       //!< Lower bound of inflight data range
    uint32_t m_inflightHi = std::numeric_limits<uint32_t>::max ();


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


    //NEW METHODS

    bool bbr_check_time_to_probe_bw();

    bool bbr_check_time_to_cruise(uint32_t bw);

    void bbr_start_bw_probe_up(const struct bbr_context* ctx);

    void bbr_start_bw_probe_down();

    void bbr_start_bw_probe_refill(uint32_t bw_probe_up_rounds);

    void bbr_start_bw_probe_cruise();

    bool bbr_has_elapsed_in_phase(simtime_t interval);

    bool bbr_is_reno_coexistence_probe_time();

    uint32_t bbr_probe_rtt_cwnd();

    void bbr_update_cycle_phase(const struct bbr_context *ctx);

    void bbr_update_latest_delivery_signals(const struct bbr_context *ctx); //NEEDED

    void bbr_set_cycle_idx(uint32_t cycle_idx);

    void bbr_check_drain(); //NEEDED

    void bbr_check_full_bw_reached(const struct bbr_context *ctx); //needed

    bool bbr_full_bw_reached();

    uint32_t getBbrState();

    double getPacingGain();

    double getCwndGain();

    uint32_t bbr_inflight(uint32_t bw, double gain); // NEEDED

    bool bbr_is_inflight_too_high(); //NEEDED

    void bbr_handle_inflight_too_high(bool rsmode);

    void bbr_probe_inflight_hi_upward();

    void bbr_raise_inflight_hi_slope();

    uint32_t bbr_target_inflight();

    uint32_t bbr_inflight_with_headroom();

    void bbr_bound_cwnd_for_inflight_model();

    void initFullPipe(); //NEEDED

    void initPacingRate(); //NEEDED

    bool bbr_is_probing_bandwidth(); //NEEDED

    void initRoundCounting(); //NEEDED

    bool modulateCwndForRecovery();

    void restoreCwnd();

    void bbr_save_cwnd();

    void bbr_set_cwnd();

    void bbr_set_pacing_rate(double gain);

    void bbr_init_lower_bounds(bool init_bw); //NEEDED

    void bbr_loss_lower_bounds(); //NEEDED

    void setSendQuantum();

    void bbr_update_congestion_signals(struct bbr_context *ctx); //NEEDED

    void bbr_check_loss_too_high_in_startup(); //NEEDED

    void bbr_advance_latest_delivery_signals(struct bbr_context *ctx);

    void bbr_handle_queue_too_high_in_startup(); //NEEDED

    void bbr_update_model(struct bbr_context *ctx); //NEEDED

    uint32_t bbr_update_round_start(); //NEEDED

    uint32_t bbr_max_bw(); //NEEDED

    void bbr_advance_max_bw_filter();

    void bbr_take_max_bw_sample(uint32_t bw); //NEEDED

    uint32_t bbr_bw();

    uint32_t bbr_bdp(uint32_t bw, double gain);

    void bbr_reset_full_bw();

    void bbr_reset_lower_bounds();

    bool bbr_adapt_upper_bounds();

    void bbr_adapt_lower_bounds(); //NEEDED

    void bbr_reset_congestion_signals();

    void bbr_calculate_bw_sample(bbr_context *ctx); //NEEDED

    void bbr_pick_probe_wait();

    void updateRTprop();

    void bbr_update_min_rtt();

    void bbr_check_probe_rtt_done();

    void bbr_exit_probe_rtt();

    void updateTargetCwnd();

    uint32_t ackAggregationCwnd();

    void bbr_update_ack_aggregation(); //NEEDED

    void bbr_exit_loss_recovery();

    void bbr_main();
  public:
    /** Constructor */
    Bbr3Flavour();

    virtual void established(bool active) override;

    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

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

