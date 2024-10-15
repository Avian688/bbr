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

#include "BbrFamily.h"

namespace inet {
namespace tcp {

std::string BbrFamilyStateVariables::str() const
{
    std::stringstream out;
    out << TcpTahoeRenoFamilyStateVariables::str();
    return out.str();
}

std::string BbrFamilyStateVariables::detailedInfo() const
{
    std::stringstream out;
    out << TcpTahoeRenoFamilyStateVariables::detailedInfo();
    return out.str();
}

// ---

BbrFamily::BbrFamily() : TcpTahoeRenoFamily(),
    state((BbrFamilyStateVariables *&)TcpTahoeRenoFamily::state)
{
}

void BbrFamily::receivedDataAck(uint32_t firstSeqAcked)
{
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);
}

void BbrFamily::receivedOutOfOrderSegment(const Ptr<const SkbInfo> skbInfo)
{
    state->ack_now = true;
    EV_INFO << "Out-of-order segment, sending immediate ACK\n";
    dynamic_cast<BbrConnection*>(conn)->sendSkbInfoAck(skbInfo);
}

void BbrFamily::receiveSeqChanged(const Ptr<const SkbInfo> skbInfo)
{
    // If we send a data segment already (with the updated seqNo) there is no need to send an additional ACK
    if (state->full_sized_segment_counter == 0 && !state->ack_now && state->last_ack_sent == state->rcv_nxt && !delayedAckTimer->isScheduled()) { // ackSent?
//        tcpEV << "ACK has already been sent (possibly piggybacked on data)\n";
    }
    else {
        // RFC 2581, page 6:
        // "3.2 Fast Retransmit/Fast Recovery
        // (...)
        // In addition, a TCP receiver SHOULD send an immediate ACK
        // when the incoming segment fills in all or part of a gap in the
        // sequence space."
        if (state->lossRecovery)
            state->ack_now = true; // although not mentioned in [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 861] seems like we have to set ack_now

        if (!state->delayed_acks_enabled) { // delayed ACK disabled
            EV_INFO << "rcv_nxt changed to " << state->rcv_nxt << ", (delayed ACK disabled) sending ACK now\n";
            dynamic_cast<BbrConnection*>(conn)->sendSkbInfoAck(skbInfo);
        }
        else { // delayed ACK enabled
            if (state->ack_now) {
                EV_INFO << "rcv_nxt changed to " << state->rcv_nxt << ", (delayed ACK enabled, but ack_now is set) sending ACK now\n";
                dynamic_cast<BbrConnection*>(conn)->sendSkbInfoAck(skbInfo);
            }
            // RFC 1122, page 96: "in a stream of full-sized segments there SHOULD be an ACK for at least every second segment."
            else if (state->full_sized_segment_counter >= 2) {
                EV_INFO << "rcv_nxt changed to " << state->rcv_nxt << ", (delayed ACK enabled, but full_sized_segment_counter=" << state->full_sized_segment_counter << ") sending ACK now\n";
                dynamic_cast<BbrConnection*>(conn)->sendSkbInfoAck(skbInfo);
            }
            else {
                EV_INFO << "rcv_nxt changed to " << state->rcv_nxt << ", (delayed ACK enabled and full_sized_segment_counter=" << state->full_sized_segment_counter << ") scheduling ACK\n";
                if (!delayedAckTimer->isScheduled()) // schedule delayed ACK timer if not already running
                    conn->scheduleAfter(0.2, delayedAckTimer); //TODO 0.2 s is default delayed ack timout, potentially increase for higher BDP
            }
        }
    }
}

void BbrFamily::receivedDuplicateAck() {
    TcpTahoeRenoFamily::receivedDuplicateAck();

    if (state->dupacks >= state->dupthresh) {
        if (!state->lossRecovery
                && (state->recoveryPoint == 0
                        || seqGE(state->snd_una, state->recoveryPoint))) {

            state->recoveryPoint = state->snd_max; // HighData = snd_max
            state->lossRecovery = true;
            EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;

            state->snd_cwnd = 3000;
            state->ssthresh = 100000000000;

            // Fast Retransmission: retransmit missing segment without waiting
            // for the REXMIT timer to expire
            conn->retransmitOneSegment(false);
        }

        conn->emit(cwndSignal, state->snd_cwnd);
        conn->emit(ssthreshSignal, state->ssthresh);

    }

    if (state->lossRecovery) {
        conn->setPipe();

        if (((int) (state->snd_cwnd / state->snd_mss)
                - (int) (state->pipe / (state->snd_mss - 12))) >= 1) { // Note: Typecast needed to avoid prohibited transmissions
            conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
        }
    }
}

bool BbrFamily::sendData(bool sendCommandInvoked)
{
    // RFC 2581, pages 7 and 8: "When TCP has not received a segment for
    // more than one retransmission timeout, cwnd is reduced to the value
    // of the restart window (RW) before transmission begins.
    // For the purposes of this standard, we define RW = IW.
    // (...)
    // Using the last time a segment was received to determine whether or
    // not to decrease cwnd fails to deflate cwnd in the common case of
    // persistent HTTP connections [HTH98].
    // (...)
    // Therefore, a TCP SHOULD set cwnd to no more than RW before beginning
    // transmission if the TCP has not sent data in an interval exceeding
    // the retransmission timeout."
    if (!conn->isSendQueueEmpty()) { // do we have any data to send?
        if ((simTime() - state->time_last_data_sent) > state->rexmit_timeout) {
            // RFC 5681, page 11: "For the purposes of this standard, we define RW = min(IW,cwnd)."
            if (state->increased_IW_enabled)
                state->snd_cwnd = state->snd_mss;//state->snd_cwnd = std::min(std::min(4 * state->snd_mss, std::max(2 * state->snd_mss, (uint32_t)4380)), state->snd_cwnd);
            else
                state->snd_cwnd = state->snd_mss;

            EV_INFO << "Restarting idle connection, CWND is set to " << state->snd_cwnd << "\n";
        }
    }

    //
    // Send window is effectively the minimum of the congestion window (cwnd)
    // and the advertised window (snd_wnd).
    //
    dynamic_cast<BbrConnection*>(conn)->sendPendingData();
    return true;
}

} // namespace tcp
} // namespace inet
