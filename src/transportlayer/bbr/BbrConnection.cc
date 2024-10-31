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

simsignal_t BbrConnection::mDeliveredSignal = registerSignal("mDelivered");
simsignal_t BbrConnection::mFirstSentTimeSignal = registerSignal("mFirstSentTime");
simsignal_t BbrConnection::mLastSentTimeSignal = registerSignal("mLastSentTime");
simsignal_t BbrConnection::msendElapsedSignal = registerSignal("msendElapsed");
simsignal_t BbrConnection::mackElapsedSignal = registerSignal("mackElapsed");
simsignal_t BbrConnection::mbytesInFlightSignal = registerSignal("mbytesInFlight");
simsignal_t BbrConnection::mbytesInFlightTotalSignal = registerSignal("mbytesInFlightTotal");
simsignal_t BbrConnection::mbytesLossSignal = registerSignal("mbytesLoss");

BbrConnection::BbrConnection() {
    // TODO Auto-generated constructor stub

}

BbrConnection::~BbrConnection() {
    // TODO Auto-generated destructor stub
}

void BbrConnection::initConnection(TcpOpenCommand *openCmd)
{
    TcpPacedConnection::initConnection(openCmd);

    m_firstSentTime = simTime();
    m_deliveredTime = simTime();
    pace = true;
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

void BbrConnection::configureStateVariables()
{
    state->dupthresh = tcpMain->par("dupthresh");
    long advertisedWindowPar = tcpMain->par("advertisedWindow");
    state->ws_support = tcpMain->par("windowScalingSupport"); // if set, this means that current host supports WS (RFC 1323)
    state->ws_manual_scale = tcpMain->par("windowScalingFactor"); // scaling factor (set manually) to help for Tcp validation
    state->ecnWillingness = tcpMain->par("ecnWillingness"); // if set, current host is willing to use ECN
    if ((!state->ws_support && advertisedWindowPar > TCP_MAX_WIN) || advertisedWindowPar <= 0 || advertisedWindowPar > TCP_MAX_WIN_SCALED)
        throw cRuntimeError("Invalid advertisedWindow parameter: %ld", advertisedWindowPar);

    state->rcv_wnd = advertisedWindowPar;
    state->rcv_adv = advertisedWindowPar;

    if (state->ws_support && advertisedWindowPar > TCP_MAX_WIN) {
        state->rcv_wnd = TCP_MAX_WIN; // we cannot to guarantee that the other end is also supporting the Window Scale (header option) (RFC 1322)
        state->rcv_adv = TCP_MAX_WIN; // therefore TCP_MAX_WIN is used as initial value for rcv_wnd and rcv_adv
    }

    state->maxRcvBuffer = advertisedWindowPar;
    state->delayed_acks_enabled = tcpMain->par("delayedAcksEnabled"); // delayed ACK algorithm (RFC 1122) enabled/disabled
    state->nagle_enabled = tcpMain->par("nagleEnabled"); // Nagle's algorithm (RFC 896) enabled/disabled
    state->limited_transmit_enabled = tcpMain->par("limitedTransmitEnabled"); // Limited Transmit algorithm (RFC 3042) enabled/disabled
    state->increased_IW_enabled = tcpMain->par("increasedIWEnabled"); // Increased Initial Window (RFC 3390) enabled/disabled
    state->snd_mss = tcpMain->par("mss"); // Maximum Segment Size (RFC 793)
    state->ts_support = tcpMain->par("timestampSupport"); // if set, this means that current host supports TS (RFC 1323)
    state->sack_support = tcpMain->par("sackSupport"); // if set, this means that current host supports SACK (RFC 2018, 2883, 3517)

    if (state->sack_support) {
        std::string algorithmName1 = "TcpReno";
        std::string algorithmName2 = "BbrFlavour";
        std::string algorithmName3 = tcpMain->par("tcpAlgorithmClass");

        if (algorithmName1 != algorithmName3 && algorithmName2 != algorithmName3) { // TODO add additional checks for new SACK supporting algorithms here once they are implemented
            EV_DEBUG << "If you want to use TCP SACK please set tcpAlgorithmClass to TcpReno\n";
            ASSERT(false);
        }
    }
}

TcpEventCode BbrConnection::processSegment1stThru8th(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    // Delegates additional processing of ECN to the algorithm
    tcpAlgorithm->processEcnInEstablished();

    //
    // RFC 793: first check sequence number
    //

    bool acceptable = true;

    if (tcpHeader->getHeaderLength() > TCP_MIN_HEADER_LENGTH) { // Header options present? TCP_HEADER_OCTETS = 20
        // PAWS
        if (state->ts_enabled) {
            uint32_t tsval = getTSval(tcpHeader);
            if (tsval != 0 && seqLess(tsval, state->ts_recent) &&
                (simTime() - state->time_last_data_sent) > PAWS_IDLE_TIME_THRESH) // PAWS_IDLE_TIME_THRESH = 24 days
            {
                EV_DETAIL << "PAWS: Segment is not acceptable, TSval=" << tsval << " in "
                          << stateName(fsm.getState()) << " state received: dropping segment\n";
                acceptable = false;
            }
        }

        readHeaderOptions(tcpHeader);
    }

    if (acceptable)
        acceptable = isSegmentAcceptable(tcpSegment, tcpHeader);

    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();

    if (!acceptable) {
        //"
        // If an incoming segment is not acceptable, an acknowledgment
        // should be sent in reply (unless the RST bit is set, if so drop
        // the segment and return):
        //
        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        //"
        if (tcpHeader->getRstBit()) {
            EV_DETAIL << "RST with unacceptable seqNum: dropping\n";
        }
        else {
            if (tcpHeader->getSynBit()) {
                EV_DETAIL << "SYN with unacceptable seqNum in " << stateName(fsm.getState()) << " state received (SYN duplicat?)\n";
            }
            else if (payloadLength > 0 && state->sack_enabled && seqLess((tcpHeader->getSequenceNo() + payloadLength), state->rcv_nxt)) {
                state->start_seqno = tcpHeader->getSequenceNo();
                state->end_seqno = tcpHeader->getSequenceNo() + payloadLength;
                state->snd_dsack = true;
                EV_DETAIL << "SND_D-SACK SET (dupseg rcvd)\n";
            }

            EV_DETAIL << "Segment seqNum not acceptable, sending ACK with current receive seq\n";
            // RFC 2018, page 4:
            // "The receiver SHOULD send an ACK for every valid segment that arrives
            // containing new data, and each of these "duplicate" ACKs SHOULD bear a
            // SACK option."
            //
            // The received segment is not "valid" therefore the ACK will not bear a SACK option, if snd_dsack (D-SACK) is not set.
            sendAck();
        }

        state->rcv_naseg++;

        emit(rcvNASegSignal, state->rcv_naseg);

        return TCP_E_IGNORE;
    }

    // ECN
    if (tcpHeader->getCwrBit() == true) {
        EV_INFO << "Received CWR... Leaving ecnEcho State\n";
        state->ecnEchoState = false;
    }

    //
    // RFC 793: second check the RST bit,
    //
    if (tcpHeader->getRstBit()) {
        // Note: if we come from LISTEN, processSegmentInListen() has already handled RST.
        switch (fsm.getState()) {
            case TCP_S_SYN_RCVD:
                //"
                // If this connection was initiated with a passive OPEN (i.e.,
                // came from the LISTEN state), then return this connection to
                // LISTEN state and return.  The user need not be informed.  If
                // this connection was initiated with an active OPEN (i.e., came
                // from SYN-SENT state) then the connection was refused, signal
                // the user "connection refused".  In either case, all segments
                // on the retransmission queue should be removed.  And in the
                // active OPEN case, enter the CLOSED state and delete the TCB,
                // and return.
                //"
                return processRstInSynReceived(tcpHeader);

            case TCP_S_ESTABLISHED:
            case TCP_S_FIN_WAIT_1:
            case TCP_S_FIN_WAIT_2:
            case TCP_S_CLOSE_WAIT:
                //"
                // If the RST bit is set then, any outstanding RECEIVEs and SEND
                // should receive "reset" responses.  All segment queues should be
                // flushed.  Users should also receive an unsolicited general
                // "connection reset" signal.
                //
                // Enter the CLOSED state, delete the TCB, and return.
                //"
                EV_DETAIL << "RST: performing connection reset, closing connection\n";
                sendIndicationToApp(TCP_I_CONNECTION_RESET);
                return TCP_E_RCV_RST; // this will trigger state transition

            case TCP_S_CLOSING:
            case TCP_S_LAST_ACK:
            case TCP_S_TIME_WAIT:
                //"
                // enter the CLOSED state, delete the TCB, and return.
                //"
                EV_DETAIL << "RST: closing connection\n";
                return TCP_E_RCV_RST; // this will trigger state transition

            default:
                ASSERT(0);
                break;
        }
    }

    // RFC 793: third check security and precedence
    // This step is ignored.

    //
    // RFC 793: fourth, check the SYN bit,
    //
    if (tcpHeader->getSynBit()
            && !(fsm.getState() == TCP_S_SYN_RCVD && tcpHeader->getAckBit())) {
        //"
        // If the SYN is in the window it is an error, send a reset, any
        // outstanding RECEIVEs and SEND should receive "reset" responses,
        // all segment queues should be flushed, the user should also
        // receive an unsolicited general "connection reset" signal, enter
        // the CLOSED state, delete the TCB, and return.
        //
        // If the SYN is not in the window this step would not be reached
        // and an ack would have been sent in the first step (sequence
        // number check).
        //"
        // Zoltan Bojthe: but accept SYN+ACK in SYN_RCVD state for simultaneous open

        ASSERT(isSegmentAcceptable(tcpSegment, tcpHeader)); // assert SYN is in the window
        EV_DETAIL << "SYN is in the window: performing connection reset, closing connection\n";
        sendIndicationToApp(TCP_I_CONNECTION_RESET);
        return TCP_E_RCV_UNEXP_SYN;
    }

    //
    // RFC 793: fifth check the ACK field,
    //
    if (!tcpHeader->getAckBit()) {
        // if the ACK bit is off drop the segment and return
        EV_INFO << "ACK not set, dropping segment\n";
        return TCP_E_IGNORE;
    }

    uint32_t old_snd_una = state->snd_una;

    TcpEventCode event = TCP_E_IGNORE;

    if (fsm.getState() == TCP_S_SYN_RCVD) {
        //"
        // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
        // and continue processing.
        //
        // If the segment acknowledgment is not acceptable, form a
        // reset segment,
        //
        //  <SEQ=SEG.ACK><CTL=RST>
        //
        // and send it.
        //"
        if (!seqLE(state->snd_una, tcpHeader->getAckNo()) || !seqLE(tcpHeader->getAckNo(), state->snd_nxt)) {
            sendRst(tcpHeader->getAckNo());
            return TCP_E_IGNORE;
        }

        // notify tcpAlgorithm and app layer
        tcpAlgorithm->established(false);

        if (isToBeAccepted())
            sendAvailableIndicationToApp();
        else
            sendEstabIndicationToApp();

        // This will trigger transition to ESTABLISHED. Timers and notifying
        // app will be taken care of in stateEntered().
        event = TCP_E_RCV_ACK;
    }

    uint32_t old_snd_nxt = state->snd_nxt; // later we'll need to see if snd_nxt changed
    // Note: If one of the last data segments is lost while already in LAST-ACK state (e.g. if using TCPEchoApps)
    // TCP must be able to process acceptable acknowledgments, however please note RFC 793, page 73:
    // "LAST-ACK STATE
    //    The only thing that can arrive in this state is an
    //    acknowledgment of our FIN.  If our FIN is now acknowledged,
    //    delete the TCB, enter the CLOSED state, and return."
    if (fsm.getState() == TCP_S_SYN_RCVD || fsm.getState() == TCP_S_ESTABLISHED ||
        fsm.getState() == TCP_S_FIN_WAIT_1 || fsm.getState() == TCP_S_FIN_WAIT_2 ||
        fsm.getState() == TCP_S_CLOSE_WAIT || fsm.getState() == TCP_S_CLOSING ||
        fsm.getState() == TCP_S_LAST_ACK)
    {
        //
        // ESTABLISHED processing:
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
        bool ok = processAckInEstabEtc(tcpSegment, tcpHeader);

        if (!ok)
            return TCP_E_IGNORE; // if acks something not yet sent, drop it
    }

    if ((fsm.getState() == TCP_S_FIN_WAIT_1 && state->fin_ack_rcvd)) {
        //"
        // FIN-WAIT-1 STATE
        //   In addition to the processing for the ESTABLISHED state, if
        //   our FIN is now acknowledged then enter FIN-WAIT-2 and continue
        //   processing in that state.
        //"
        event = TCP_E_RCV_ACK; // will trigger transition to FIN-WAIT-2
    }

    if (fsm.getState() == TCP_S_FIN_WAIT_2) {
        //"
        // FIN-WAIT-2 STATE
        //  In addition to the processing for the ESTABLISHED state, if
        //  the retransmission queue is empty, the user's CLOSE can be
        //  acknowledged ("ok") but do not delete the TCB.
        //"
        // nothing to do here (in our model, used commands don't need to be
        // acknowledged)
    }

    if (fsm.getState() == TCP_S_CLOSING) {
        //"
        // In addition to the processing for the ESTABLISHED state, if
        // the ACK acknowledges our FIN then enter the TIME-WAIT state,
        // otherwise ignore the segment.
        //"
        if (state->fin_ack_rcvd) {
            EV_INFO << "Our FIN acked -- can go to TIME_WAIT now\n";
            event = TCP_E_RCV_ACK; // will trigger transition to TIME-WAIT
            scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer); // start timer

            // we're entering TIME_WAIT, so we can signal CLOSED the user
            // (the only thing left to do is wait until the 2MSL timer expires)
        }
    }

    if (fsm.getState() == TCP_S_LAST_ACK) {
        //"
        // The only thing that can arrive in this state is an
        // acknowledgment of our FIN.  If our FIN is now acknowledged,
        // delete the TCB, enter the CLOSED state, and return.
        //"
        if (state->send_fin && tcpHeader->getAckNo() == state->snd_fin_seq + 1) {
            EV_INFO << "Last ACK arrived\n";
            return TCP_E_RCV_ACK; // will trigger transition to CLOSED
        }
    }

    if (fsm.getState() == TCP_S_TIME_WAIT) {
        //"
        // The only thing that can arrive in this state is a
        // retransmission of the remote FIN.  Acknowledge it, and restart
        // the 2 MSL timeout.
        //"
        // And we are staying in the TIME_WAIT state.
        //
        sendAck();
        rescheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);
    }

    //
    // RFC 793: sixth, check the URG bit,
    //
    if (tcpHeader->getUrgBit() && (fsm.getState() == TCP_S_ESTABLISHED ||
                                   fsm.getState() == TCP_S_FIN_WAIT_1 || fsm.getState() == TCP_S_FIN_WAIT_2))
    {
        //"
        // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
        // the user that the remote side has urgent data if the urgent
        // pointer (RCV.UP) is in advance of the data consumed.  If the
        // user has already been signaled (or is still in the "urgent
        // mode") for this continuous sequence of urgent data, do not
        // signal the user again.
        //"

        // TODO URG currently not supported
    }

    //
    // RFC 793: seventh, process the segment text,
    //
    uint32_t old_rcv_nxt = state->rcv_nxt; // if rcv_nxt changes, we need to send/schedule an ACK

    if (fsm.getState() == TCP_S_SYN_RCVD || fsm.getState() == TCP_S_ESTABLISHED ||
        fsm.getState() == TCP_S_FIN_WAIT_1 || fsm.getState() == TCP_S_FIN_WAIT_2)
    {
        //"
        // Once in the ESTABLISHED state, it is possible to deliver segment
        // text to user RECEIVE buffers.  Text from segments can be moved
        // into buffers until either the buffer is full or the segment is
        // empty.  If the segment empties and carries an PUSH flag, then
        // the user is informed, when the buffer is returned, that a PUSH
        // has been received.
        //
        // When the TCP takes responsibility for delivering the data to the
        // user it must also acknowledge the receipt of the data.
        //
        // Once the TCP takes responsibility for the data it advances
        // RCV.NXT over the data accepted, and adjusts RCV.WND as
        // appropriate to the current buffer availability.  The total of
        // RCV.NXT and RCV.WND should not be reduced.
        //
        // Please note the window management suggestions in section 3.7.
        //
        // Send an acknowledgment of the form:
        //
        //   <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        //
        // This acknowledgment should be piggybacked on a segment being
        // transmitted if possible without incurring undue delay.
        //"

        if (payloadLength > 0) {
            // check for full sized segment
            if ((uint32_t)payloadLength == state->snd_mss || (uint32_t)payloadLength + B(tcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get() == state->snd_mss)
                state->full_sized_segment_counter++;

            // check for persist probe
            if (payloadLength == 1)
                state->ack_now = true; // TODO how to check if it is really a persist probe?

            updateRcvQueueVars();

            if (hasEnoughSpaceForSegmentInReceiveQueue(tcpSegment, tcpHeader)) { // enough freeRcvBuffer in rcvQueue for new segment?
                EV_DETAIL << "Processing segment text in a data transfer state\n";

                // insert into receive buffers. If this segment is contiguous with
                // previously received ones (seqNo == rcv_nxt), rcv_nxt can be increased;
                // otherwise it stays the same but the data must be cached nevertheless
                // (to avoid "Failure to retain above-sequence data" problem, RFC 2525
                // section 2.5).

                uint32_t old_usedRcvBuffer = state->usedRcvBuffer;
                state->rcv_nxt = receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader);

                if (seqGreater(state->snd_una, old_snd_una)) {
                    // notify

                    tcpAlgorithm->receivedDataAck(old_snd_una);

                    // in the receivedDataAck we need the old value
                    state->dupacks = 0;

                    emit(dupAcksSignal, state->dupacks);
                }

                // out-of-order segment?
                if (old_rcv_nxt == state->rcv_nxt) {
                    state->rcv_oooseg++;

                    emit(rcvOooSegSignal, state->rcv_oooseg);

                    // RFC 2018, page 4:
                    // "The receiver SHOULD send an ACK for every valid segment that arrives
                    // containing new data, and each of these "duplicate" ACKs SHOULD bear a
                    // SACK option."
                    if (state->sack_enabled) {
                        // store start and end sequence numbers of current oooseg in state variables
                        state->start_seqno = tcpHeader->getSequenceNo();
                        state->end_seqno = tcpHeader->getSequenceNo() + payloadLength;

                        if (old_usedRcvBuffer == receiveQueue->getAmountOfBufferedBytes()) { // D-SACK
                            state->snd_dsack = true;
                            EV_DETAIL << "SND_D-SACK SET (old_rcv_nxt == rcv_nxt duplicated oooseg rcvd)\n";
                        }
                        else { // SACK
                            state->snd_sack = true;
                            EV_DETAIL << "SND_SACK SET (old_rcv_nxt == rcv_nxt oooseg rcvd)\n";
                        }
                    }

                    dynamic_cast<BbrFamily*>(tcpAlgorithm)->receivedOutOfOrderSegment(tcpHeader->getTag<SkbInfo>());
                }
                else {
                    // forward data to app
                    //
                    // FIXME observe PSH bit
                    //
                    // FIXME we should implement socket READ command, and pass up only
                    // as many bytes as requested. rcv_wnd should be decreased
                    // accordingly!
                    //
                    if (!isToBeAccepted())
                        sendAvailableDataToApp();

                    // if this segment "filled the gap" until the previously arrived segment
                    // that carried a FIN (i.e.rcv_nxt == rcv_fin_seq), we have to advance
                    // rcv_nxt over the FIN.
                    if (state->fin_rcvd && state->rcv_nxt == state->rcv_fin_seq) {
                        state->ack_now = true; // although not mentioned in [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 861] seems like we have to set ack_now
                        EV_DETAIL << "All segments arrived up to the FIN segment, advancing rcv_nxt over the FIN\n";
                        state->rcv_nxt = state->rcv_fin_seq + 1;
                        // state transitions will be done in the state machine, here we just set
                        // the proper event code (TCP_E_RCV_FIN or TCP_E_RCV_FIN_ACK)
                        event = TCP_E_RCV_FIN;

                        switch (fsm.getState()) {
                            case TCP_S_FIN_WAIT_1:
                                if (state->fin_ack_rcvd) {
                                    event = TCP_E_RCV_FIN_ACK;
                                    // start the time-wait timer, turn off the other timers
                                    cancelEvent(finWait2Timer);
                                    scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                                    // we're entering TIME_WAIT, so we can signal CLOSED the user
                                    // (the only thing left to do is wait until the 2MSL timer expires)
                                }
                                break;

                            case TCP_S_FIN_WAIT_2:
                                // Start the time-wait timer, turn off the other timers.
                                cancelEvent(finWait2Timer);
                                scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                                // we're entering TIME_WAIT, so we can signal CLOSED the user
                                // (the only thing left to do is wait until the 2MSL timer expires)
                                break;

                            case TCP_S_TIME_WAIT:
                                // Restart the 2 MSL time-wait timeout.
                                rescheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);
                                break;

                            default:
                                break;
                        }
                    }
                }
            }
            else { // not enough freeRcvBuffer in rcvQueue for new segment
                state->tcpRcvQueueDrops++; // update current number of tcp receive queue drops

                emit(tcpRcvQueueDropsSignal, state->tcpRcvQueueDrops);

                // if the ACK bit is off drop the segment and return
                EV_WARN << "RcvQueueBuffer has run out, dropping segment\n";
                return TCP_E_IGNORE;
            }
        }
    }

    //
    // RFC 793: eighth, check the FIN bit,
    //
    if (tcpHeader->getFinBit()) {
        state->ack_now = true;

        //"
        // If the FIN bit is set, signal the user "connection closing" and
        // return any pending RECEIVEs with same message, advance RCV.NXT
        // over the FIN, and send an acknowledgment for the FIN.  Note that
        // FIN implies PUSH for any segment text not yet delivered to the
        // user.
        //"

        // Note: seems like RFC 793 is not entirely correct here: if the
        // segment is "above sequence" (ie. RCV.NXT < SEG.SEQ), we cannot
        // advance RCV.NXT over the FIN. Instead we remember this sequence
        // number and do it later.
        uint32_t fin_seq = (uint32_t)tcpHeader->getSequenceNo() + (uint32_t)payloadLength;

        if (state->rcv_nxt == fin_seq) {
            // advance rcv_nxt over FIN now
            EV_INFO << "FIN arrived, advancing rcv_nxt over the FIN\n";
            state->rcv_nxt++;
            // state transitions will be done in the state machine, here we just set
            // the proper event code (TCP_E_RCV_FIN or TCP_E_RCV_FIN_ACK)
            event = TCP_E_RCV_FIN;

            switch (fsm.getState()) {
                case TCP_S_FIN_WAIT_1:
                    if (state->fin_ack_rcvd) {
                        event = TCP_E_RCV_FIN_ACK;
                        // start the time-wait timer, turn off the other timers
                        cancelEvent(finWait2Timer);
                        scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                        // we're entering TIME_WAIT, so we can signal CLOSED the user
                        // (the only thing left to do is wait until the 2MSL timer expires)
                    }
                    break;

                case TCP_S_FIN_WAIT_2:
                    // Start the time-wait timer, turn off the other timers.
                    cancelEvent(finWait2Timer);
                    scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                    // we're entering TIME_WAIT, so we can signal CLOSED the user
                    // (the only thing left to do is wait until the 2MSL timer expires)
                    break;

                case TCP_S_TIME_WAIT:
                    // Restart the 2 MSL time-wait timeout.
                    rescheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);
                    break;

                default:
                    break;
            }
        }
        else {
            // we'll have to do it later (when an arriving segment "fills the gap")
            EV_DETAIL << "FIN segment above sequence, storing sequence number of FIN\n";
            state->fin_rcvd = true;
            state->rcv_fin_seq = fin_seq;
        }

        // TODO do PUSH stuff
    }

    if (old_rcv_nxt != state->rcv_nxt) {
        // if rcv_nxt changed, either because we received segment text or we
        // received a FIN that needs to be acked (or both), we need to send or
        // schedule an ACK.
        if (state->sack_enabled) {
            if (receiveQueue->getQueueLength() != 0) {
                // RFC 2018, page 4:
                // "If sent at all, SACK options SHOULD be included in all ACKs which do
                // not ACK the highest sequence number in the data receiver's queue."
                state->start_seqno = tcpHeader->getSequenceNo();
                state->end_seqno = tcpHeader->getSequenceNo() + payloadLength;
                state->snd_sack = true;
                EV_DETAIL << "SND_SACK SET (rcv_nxt changed, but receiveQ is not empty)\n";
                state->ack_now = true; // although not mentioned in [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 861] seems like we have to set ack_now
            }
        }

        // tcpAlgorithm decides when and how to do ACKs

        dynamic_cast<BbrFamily*>(tcpAlgorithm)->receiveSeqChanged(tcpHeader->getTag<SkbInfo>());
        //}
    }

    if ((fsm.getState() == TCP_S_ESTABLISHED || fsm.getState() == TCP_S_SYN_RCVD) &&
        state->send_fin && state->snd_nxt == state->snd_fin_seq + 1)
    {
        // if the user issued the CLOSE command a long time ago and we've just
        // managed to send off FIN, we simulate a CLOSE command now (we had to
        // defer it at that time because we still had data in the send queue.)
        // This CLOSE will take us into the FIN_WAIT_1 state.
        EV_DETAIL << "Now we can do the CLOSE which was deferred a while ago\n";
        event = TCP_E_CLOSE;
    }

    if (fsm.getState() == TCP_S_CLOSE_WAIT && state->send_fin &&
        state->snd_nxt == state->snd_fin_seq + 1 && old_snd_nxt != state->snd_nxt)
    {
        // if we're in CLOSE_WAIT and we just got to sent our long-pending FIN,
        // we simulate a CLOSE command now (we had to defer it at that time because
        // we still had data in the send queue.) This CLOSE will take us into the
        // LAST_ACK state.
        EV_DETAIL << "Now we can do the CLOSE which was deferred a while ago\n";
        event = TCP_E_CLOSE;
    }

    return event;
}

bool BbrConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";

    uint64_t previousDelivered = m_delivered;  //RATE SAMPLER SPECIFIC STUFF
    uint32_t previousLost = m_bytesLoss; //TODO Create Sack method to get exact amount of lost packets
    uint32_t priorInFlight = m_bytesInFlight;//get current BytesInFlight somehow
    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();

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
//
//            if((tcpHeader->findTag<SkbInfo>())){
//                skbDelivered(tcpHeader->getTag<SkbInfo>());
//            }

            updateWndInfo(tcpHeader);
            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;

            updateInFlight();

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;

            updateSample(currentDelivered, lost, false, priorInFlight, dynamic_cast<BbrFamily*>(tcpAlgorithm)->getConnMinRtt());

            tcpAlgorithm->receivedDuplicateAck();
        }
        else {
            // if doesn't qualify as duplicate ACK, just ignore it.
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo())
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                else if (state->snd_una == state->snd_max)
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
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

        // acked data no longer needed in send queue

        sendQueue->discardUpTo(discardUpToSeq);

        // acked data no longer needed in rexmit queue
        if (state->sack_enabled){
            rexmitQueue->discardUpTo(discardUpToSeq);
        }

        if((tcpHeader->findTag<SkbInfo>())){
            skbDelivered(tcpHeader->getTag<SkbInfo>());
        }
        updateWndInfo(tcpHeader);
        uint32_t currentDelivered  = m_delivered - previousDelivered;
        m_lastAckedSackedBytes = currentDelivered;
        // if segment contains data, wait until data has been forwarded to app before sending ACK,
        // otherwise we would use an old ACKNo
        updateInFlight();

        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {
            // notify

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;

            updateSample(currentDelivered, lost, false, priorInFlight, dynamic_cast<BbrFamily*>(tcpAlgorithm)->getConnMinRtt());

            dynamic_cast<BbrFamily*>(tcpAlgorithm)->receivedDataAck(old_snd_una);
            // in the receivedDataAck we need the old value
            state->dupacks = 0;

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
        sendPendingData();
        return false; // means "drop"
    }
    sendPendingData();
    return true;
}

void BbrConnection::skbDelivered(const Ptr<const SkbInfo> skbInfo)
{
    if(skbInfo->getDeliveredTime() != SIMTIME_MAX){

        m_delivered += skbInfo->getPayloadBytes();
        m_deliveredTime = simTime();

        if (m_rateSample.m_priorDelivered == 0 || skbInfo->getDelivered() > m_rateSample.m_priorDelivered)
        {
            m_rateSample.m_ackElapsed = simTime() - skbInfo->getDeliveredTime();
            m_rateSample.m_priorDelivered = skbInfo->getDelivered();
            m_rateSample.m_priorTime = skbInfo->getDeliveredTime();
            m_rateSample.m_sendElapsed = skbInfo->getLastSent() - skbInfo->getFirstSent();
            m_rateSample.m_isAppLimited = skbInfo->isAppLimited();
            m_firstSentTime = skbInfo->getLastSent();

            emit(msendElapsedSignal, m_rateSample.m_sendElapsed);
            emit(mackElapsedSignal, m_rateSample.m_ackElapsed);
            emit(mFirstSentTimeSignal, skbInfo->getFirstSent());
            emit(mLastSentTimeSignal, skbInfo->getLastSent());
        }

        m_txItemDelivered = skbInfo->getDelivered();
    }
}


void BbrConnection::sendSkbInfoAck(const Ptr<const SkbInfo> skbInfo)
{
    const auto& tcpHeader = makeShared<TcpHeader>();

    tcpHeader->setAckBit(true);
    tcpHeader->setSequenceNo(state->snd_nxt);
    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setWindow(updateRcvWnd());
    //std::cout << "\n Trying to send ACK, final ACK vector size " << intDataDup.size() << endl;

    // rfc-3168, pages 19-20:
    // When TCP receives a CE data packet at the destination end-system, the
    // TCP data receiver sets the ECN-Echo flag in the TCP header of the
    // subsequent ACK packet.
    // ...
    // After a TCP receiver sends an ACK packet with the ECN-Echo bit set,
    // that TCP receiver continues to set the ECN-Echo flag in all the ACK
    // packets it sends (whether they acknowledge CE data packets or non-CE
    // data packets) until it receives a CWR packet (a packet with the CWR
    // flag set).  After the receipt of the CWR packet, acknowledgments for
    // subsequent non-CE data packets do not have the ECN-Echo flag set.

    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpAlgorithm->shouldMarkAck()) {
            tcpHeader->setEceBit(true);
            EV_INFO << "In ecnEcho state... send ACK with ECE bit set\n";
        }
    }

    // write header options
    //std::cout << "\nSending Ack (after options)..." << tcpHeader->str() << endl;
    writeHeaderOptions(tcpHeader);

    tcpHeader->addTagIfAbsent<SkbInfo>()->setDelivered(skbInfo->getDelivered());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setFirstSent(skbInfo->getFirstSent());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setLastSent(skbInfo->getLastSent());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setDeliveredTime(skbInfo->getDeliveredTime());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setPayloadBytes(skbInfo->getPayloadBytes());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setIsAppLimited((m_appLimited != 0));
    Packet *fp = new Packet("TcpAck");
    // rfc-3168 page 20: pure ack packets must be sent with not-ECT codepoint
    state->sndAck = true;

    // send it

    //std::cout << "\nSending Ack (after options)..." << tcpHeader->str() << endl;
    sendToIP(fp, tcpHeader);

    state->sndAck = false;

    // notify
    tcpAlgorithm->ackSent();
}

void BbrConnection::calculateAppLimited()
{
    uint32_t cWnd = dynamic_cast<BbrFlavour*>(tcpAlgorithm)->getCwnd();
    uint32_t in_flight = m_bytesInFlight;
    const uint32_t lostOut = m_bytesLoss;
    uint32_t segmentSize = state->snd_mss;
    const uint32_t retransOut = 0;
    //const uint32_t tailSeq;
    //const uint32_t nextTx;

    /* Missing checks from Linux:
     * - Nothing in sending host's qdisc queues or NIC tx queue. NOT IMPLEMENTED
     */
    //tailSeq - nextTx < static_cast<int32_t>(segmentSize) &&
    if (in_flight < cWnd && lostOut <= retransOut)             // All lost packets have been retransmitted.
    {
        m_appLimited = std::max<uint32_t>(m_delivered + in_flight, 1);
    }
}

uint32_t BbrConnection::sendSegment(uint32_t bytes)
{
    // FIXME check it: where is the right place for the next code (sacked/rexmitted)
    if (state->sack_enabled && state->afterRto) {
        // check rexmitQ and try to forward snd_nxt before sending new data
        uint32_t forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);

        if (forward > 0) {
            EV_INFO << "sendSegment(" << bytes << ") forwarded " << forward << " bytes of snd_nxt from " << state->snd_nxt;
            state->snd_nxt += forward;
            EV_INFO << " to " << state->snd_nxt << endl;
            EV_DETAIL << rexmitQueue->detailedInfo();
        }
    }

    uint32_t buffered = sendQueue->getBytesAvailable(state->snd_nxt);

    if (bytes > buffered) // last segment?
        bytes = buffered;

    // if header options will be added, this could reduce the number of data bytes allowed for this segment,
    // because following condition must to be respected:
    //     bytes + options_len <= snd_mss
    const auto& tmpTcpHeader = makeShared<TcpHeader>();
    tmpTcpHeader->setAckBit(true); // needed for TS option, otherwise TSecr will be set to 0
    writeHeaderOptions(tmpTcpHeader);
    uint options_len = B(tmpTcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get();

    ASSERT(options_len < state->snd_mss);

    //if (bytes + options_len > state->snd_mss)
    //    bytes = state->snd_mss - options_len;
    bytes = state->snd_mss;
    uint32_t sentBytes = bytes;

    // send one segment of 'bytes' bytes from snd_nxt, and advance snd_nxt
    Packet *tcpSegment = sendQueue->createSegmentWithBytes(state->snd_nxt, bytes);
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->snd_nxt);
    ASSERT(tcpHeader != nullptr);

    // Remember old_snd_next to store in SACK rexmit queue.
    uint32_t old_snd_nxt = state->snd_nxt;

    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setAckBit(true);
    tcpHeader->setWindow(updateRcvWnd());

    // ECN
//    if (state->ect && state->sndCwr) {
//        tcpHeader->setCwrBit(true);
//        EV_INFO << "\nDCTCPInfo - sending TCP segment. Set CWR bit. Setting sndCwr to false\n";
//        state->sndCwr = false;
//    }

    // TODO when to set PSH bit?
    // TODO set URG bit if needed
    ASSERT(bytes == tcpSegment->getByteLength());

    state->snd_nxt += bytes;

    // check if afterRto bit can be reset
    if (state->afterRto && seqGE(state->snd_nxt, state->snd_max))
        state->afterRto = false;

    if (state->send_fin && state->snd_nxt == state->snd_fin_seq) {
        EV_DETAIL << "Setting FIN on segment\n";
        tcpHeader->setFinBit(true);
        state->snd_nxt = state->snd_fin_seq + 1;
    }

    // if sack_enabled copy region of tcpHeader to rexmitQueue
    if (state->sack_enabled)
        rexmitQueue->enqueueSentData(old_snd_nxt, state->snd_nxt);

    // add header options and update header length (from tcpseg_temp)
    for (uint i = 0; i < tmpTcpHeader->getHeaderOptionArraySize(); i++)
        tcpHeader->appendHeaderOption(tmpTcpHeader->getHeaderOption(i)->dup());
    tcpHeader->setHeaderLength(TCP_MIN_HEADER_LENGTH + tcpHeader->getHeaderOptionArrayLength());
    tcpHeader->setChunkLength(B(tcpHeader->getHeaderLength()));

    ASSERT(tcpHeader->getHeaderLength() == tmpTcpHeader->getHeaderLength());

//    tcpHeader->addTagIfAbsent<SkbInfo>()->setFirstSent(m_firstSentTime);
//    tcpHeader->addTagIfAbsent<SkbInfo>()->setLastSent(simTime());
//    tcpHeader->addTagIfAbsent<SkbInfo>()->setDeliveredTime(m_deliveredTime);
//    tcpHeader->addTagIfAbsent<SkbInfo>()->setDelivered(m_delivered);
//    tcpHeader->addTagIfAbsent<SkbInfo>()->setPayloadBytes(bytes);

    // send it
    //addSkbInfoTags(tcpHeader, bytes);

    if(pace){
        tcpHeader->addTagIfAbsent<SkbInfo>()->setFirstSent(m_firstSentTime);
        tcpHeader->addTagIfAbsent<SkbInfo>()->setLastSent(simTime());
        tcpHeader->addTagIfAbsent<SkbInfo>()->setDeliveredTime(m_deliveredTime);
        tcpHeader->addTagIfAbsent<SkbInfo>()->setDelivered(m_delivered);
        tcpHeader->addTagIfAbsent<SkbInfo>()->setPayloadBytes(bytes);
    }

    sendToIP(tcpSegment, tcpHeader);

    // let application fill queue again, if there is space
    const uint32_t alreadyQueued = sendQueue->getBytesAvailable(sendQueue->getBufferStartSeq());
    const uint32_t abated = (state->sendQueueLimit > alreadyQueued) ? state->sendQueueLimit - alreadyQueued : 0;
    if ((state->sendQueueLimit > 0) && !state->queueUpdate && (abated >= state->snd_mss)) { // request more data if space >= 1 MSS
        // Tell upper layer readiness to accept more data
        sendIndicationToApp(TCP_I_SEND_MSG, abated);
        state->queueUpdate = true;
    }

    // remember highest seq sent (snd_nxt may be set back on retransmission,
    // but we'll need snd_max to check validity of ACKs -- they must ack
    // something we really sent)
    if (seqGreater(state->snd_nxt, state->snd_max))
        state->snd_max = state->snd_nxt;

    return sentBytes;
}

bool BbrConnection::sendDataDuringLossRecovery(uint32_t congestionWindow)
{
    ASSERT(state->sack_enabled && state->lossRecovery);

    // RFC 3517 pages 7 and 8: "(5) In order to take advantage of potential additional available
    // cwnd, proceed to step (C) below.
    // (...)
    // (C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
    // segments as follows:
    // (...)
    // (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)"
    if (((int)congestionWindow - (int)m_bytesInFlight) >= (int)state->snd_mss) { // Note: Typecast needed to avoid prohibited transmissions
        // RFC 3517 pages 7 and 8: "(C.1) The scoreboard MUST be queried via NextSeg () for the
        // sequence number range of the next segment to transmit (if any),
        // and the given segment sent.  If NextSeg () returns failure (no
        // data to send) return without sending anything (i.e., terminate
        // steps C.1 -- C.5)."

        uint32_t seqNum;

        if (!nextSeg(seqNum)) // if nextSeg() returns false (=failure): terminate steps C.1 -- C.5
            return false;

        uint32_t sentBytes = sendSegmentDuringLossRecoveryPhase(seqNum);
        if(sentBytes > 0){
            return true;
        }
        else{
            return false;
        }
        //m_bytesInFlight += sentBytes;
        //state->pipe = m_bytesInFlight;
        // RFC 3517 page 8: "(C.4) The estimate of the amount of data outstanding in the
        // network must be updated by incrementing pipe by the number of
        // octets transmitted in (C.1)."
    }
    else{
        return false;
    }
}

void BbrConnection::updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt) //GenerateSample in ns3 rate sampler
{
    if(m_appLimited != 0 && m_delivered > m_appLimited){ //NOT NEEDED
        m_appLimited = 0;
    }

    m_rateSample.m_ackedSacked = delivered; /* freshly ACKed or SACKed */
    m_rateSample.m_bytesLoss = lost;        /* freshly marked lost */
    m_rateSample.m_priorInFlight = priorInFlight;

    /* Return an invalid sample if no timing information is available or
     * in recovery from loss with SACK reneging. Rate samples taken during
     * a SACK reneging event may overestimate bw by including packets that
     * were SACKed before the reneg.
     */
    if (m_rateSample.m_priorTime == 0 || is_sack_reneg) {
        m_rateSample.m_delivered = -1;
        m_rateSample.m_interval = 0;
        return;
    }

    // LINUX:
    //  /* Model sending data and receiving ACKs as separate pipeline phases
    //   * for a window. Usually the ACK phase is longer, but with ACK
    //   * compression the send phase can be longer. To be safe we use the
    //   * longer phase.
    //   */
    //  auto snd_us = m_rateSample.m_interval;  /* send phase */
    //  auto ack_us = Simulator::Now () - m_rateSample.m_prior_mstamp;
    //  m_rateSample.m_interval = std::max (snd_us, ack_us);

    m_rateSample.m_interval = std::max(m_rateSample.m_sendElapsed, m_rateSample.m_ackElapsed);
    m_rateSample.m_delivered = m_delivered - m_rateSample.m_priorDelivered;

    /* Normally we expect m_interval >= minRtt.
     * Note that rate may still be over-estimated when a spuriously
     * retransmitted skb was first (s)acked because "interval_us"
     * is under-estimated (up to an RTT). However continuously
     * measuring the delivery rate during loss recovery is crucial
     * for connections suffer heavy or prolonged losses.
     */
    if(m_rateSample.m_interval < minRtt) {
        m_rateSample.m_interval = 0;
        m_rateSample.m_priorTime = 0; // To make rate sample invalid
        return;
    }

    /* Record the last non-app-limited or the highest app-limited bw */
    if (!m_rateSample.m_isAppLimited || (m_rateSample.m_delivered * m_rateInterval >= m_rateDelivered * m_rateSample.m_interval)) {
        m_rateDelivered = m_rateSample.m_delivered;
        m_rateInterval = m_rateSample.m_interval;
        m_rateAppLimited = m_rateSample.m_isAppLimited;
        m_rateSample.m_deliveryRate = m_rateSample.m_delivered / m_rateSample.m_interval;
    }
}

void BbrConnection::updateInFlight() {
    ASSERT(state->sack_enabled);
    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    uint32_t currentInFlight = 0;
    uint32_t bytesLoss = 0;
    uint32_t length = 0; // required for rexmitQueue->checkSackBlock()
    bool sacked; // required for rexmitQueue->checkSackBlock()
    bool rexmitted; // required for rexmitQueue->checkSackBlock()


//    uint32_t startVal = state->snd_una;
//    if(packetQueue.size() > 0){
//        Packet* packet = packetQueue.back();
//        startVal = packet->peekAtFront<tcp::TcpHeader>()->getSequenceNo();
//    }
    //check front of queue and get largest seq number in queue?

    rexmitQueue->updateLost(rexmitQueue->getHighestSackedSeqNum());

    for (uint32_t s1 = state->snd_una; seqLess(s1, state->snd_max); s1 +=
            length) {
        rexmitQueue->checkSackBlock(s1, length, sacked, rexmitted);
        if(length == 0){
            break;
        }
        if (!sacked) {
            //if (isLost(s1) == false){
            const std::tuple<bool, bool> item = rexmitQueue->getLostAndRetransmitted(s1);
            bool isLost = std::get<0>(item);
            bool isRetans = std::get<1>(item);
            if(!isLost || isRetans) {
                currentInFlight += length;
            }

            if(isLost){
                bytesLoss += length;
            }
            // RFC 3517, pages 3 and 4: "(b) If S1 <= HighRxt:
            //
            //     Pipe is incremented by 1 octet.
            //
            //     The effect of this condition is that pipe is incremented for
            //     the retransmission of the octet.
            //
            //  Note that octets retransmitted without being considered lost are
            //  counted twice by the above mechanism."
//            if (seqLess(s1, state->highRxt)){
//                currentInFlight += length;
//            }
        }
    }
//    uint32_t paceBufferedQueueSize = packetQueue.size() * (state->snd_mss);
//    //if(currentInFlight < bufferedBytes){
//    //    m_bytesInFlight = state->snd_mss;//-12;
//    //}
//    //else{
//    if(currentInFlight < bufferedBytes){
//        m_bytesInFlight = 0;
//    }
//    else{
//        m_bytesInFlight = currentInFlight - bufferedBytes;
//    }
    //}
    m_bytesInFlight = currentInFlight;
    state->pipe = m_bytesInFlight;
    m_bytesLoss = bytesLoss;

    //std::cout << "\n BBR in flight: " << m_bytesInFlight << endl;

    //m_bytesInFlight = rexmitQueue->getInFlight();
    emit(mbytesInFlightSignal, m_bytesInFlight);
    emit(mbytesLossSignal, m_bytesLoss);
}

simtime_t BbrConnection::getFirstSent() {
    return m_firstSentTime;
}

simtime_t BbrConnection::getDeliveredTime() {
    return m_deliveredTime;
}

uint32_t BbrConnection::getDelivered() {
    return m_delivered;
}

BbrConnection::RateSample BbrConnection::getRateSample() {
    return m_rateSample;
}

uint32_t BbrConnection::getBytesInFlight() {
    return m_bytesInFlight;
}

uint32_t BbrConnection::getLastAckedSackedBytes() {
    return m_lastAckedSackedBytes;
}

void BbrConnection::addSkbInfoTags(const Ptr<TcpHeader> &tcpHeader, uint32_t payloadBytes) {
    tcpHeader->addTagIfAbsent<SkbInfo>()->setFirstSent(m_firstSentTime);
    tcpHeader->addTagIfAbsent<SkbInfo>()->setLastSent(simTime());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setDeliveredTime(m_deliveredTime);
    tcpHeader->addTagIfAbsent<SkbInfo>()->setDelivered(m_delivered);
    tcpHeader->addTagIfAbsent<SkbInfo>()->setPayloadBytes(payloadBytes);
}

void BbrConnection::setPipe() {
    updateInFlight();
}

bool BbrConnection::processSACKOption(const Ptr<const TcpHeader>& tcpHeader, const TcpOptionSack& option)
{
    if (option.getLength() % 8 != 2) {
        EV_ERROR << "ERROR: option length incorrect\n";
        return false;
    }

    uint n = option.getSackItemArraySize();
    ASSERT(option.getLength() == 2 + n * 8);

    if (!state->sack_enabled) {
        EV_ERROR << "ERROR: " << n << " SACK(s) received, but sack_enabled is set to false\n";
        return false;
    }

    if (fsm.getState() != TCP_S_SYN_RCVD && fsm.getState() != TCP_S_ESTABLISHED
        && fsm.getState() != TCP_S_FIN_WAIT_1 && fsm.getState() != TCP_S_FIN_WAIT_2)
    {
        EV_ERROR << "ERROR: Tcp Header Option SACK received, but in unexpected state\n";
        return false;
    }

    if (n > 0) { // sacks present?
        EV_INFO << n << " SACK(s) received:\n";
        for (uint i = 0; i < n; i++) {
            Sack tmp;
            tmp.setStart(option.getSackItem(i).getStart());
            tmp.setEnd(option.getSackItem(i).getEnd());

            EV_INFO << (i + 1) << ". SACK: " << tmp.str() << endl;

            // check for D-SACK
            if (i == 0 && seqLE(tmp.getEnd(), tcpHeader->getAckNo())) {
                // RFC 2883, page 8:
                // "In order for the sender to check that the first (D)SACK block of an
                // acknowledgement in fact acknowledges duplicate data, the sender
                // should compare the sequence space in the first SACK block to the
                // cumulative ACK which is carried IN THE SAME PACKET.  If the SACK
                // sequence space is less than this cumulative ACK, it is an indication
                // that the segment identified by the SACK block has been received more
                // than once by the receiver.  An implementation MUST NOT compare the
                // sequence space in the SACK block to the TCP state variable snd.una
                // (which carries the total cumulative ACK), as this may result in the
                // wrong conclusion if ACK packets are reordered."
                EV_DETAIL << "Received D-SACK below cumulative ACK=" << tcpHeader->getAckNo()
                          << " D-SACK: " << tmp.str() << endl;
                // Note: RFC 2883 does not specify what should be done in this case.
                // RFC 2883, page 9:
                // "5. Detection of Duplicate Packets
                // (...) This document does not specify what action a TCP implementation should
                // take in these cases. The extension to the SACK option simply enables
                // the sender to detect each of these cases.(...)"
            }
            else if (i == 0 && n > 1 && seqGreater(tmp.getEnd(), tcpHeader->getAckNo())) {
                // RFC 2883, page 8:
                // "If the sequence space in the first SACK block is greater than the
                // cumulative ACK, then the sender next compares the sequence space in
                // the first SACK block with the sequence space in the second SACK
                // block, if there is one.  This comparison can determine if the first
                // SACK block is reporting duplicate data that lies above the cumulative
                // ACK."
                Sack tmp2(option.getSackItem(1).getStart(), option.getSackItem(1).getEnd());

                if (tmp2.contains(tmp)) {
                    EV_DETAIL << "Received D-SACK above cumulative ACK=" << tcpHeader->getAckNo()
                              << " D-SACK: " << tmp.str()
                              << ", SACK: " << tmp2.str() << endl;
                    // Note: RFC 2883 does not specify what should be done in this case.
                    // RFC 2883, page 9:
                    // "5. Detection of Duplicate Packets
                    // (...) This document does not specify what action a TCP implementation should
                    // take in these cases. The extension to the SACK option simply enables
                    // the sender to detect each of these cases.(...)"
                }
            }

            if (seqGreater(tmp.getEnd(), tcpHeader->getAckNo()) && seqGreater(tmp.getEnd(), state->snd_una)){
                rexmitQueue->setSackedBit(tmp.getStart(), tmp.getEnd());
//                if((tcpHeader->findTag<SkbInfo>())){
//                    skbDelivered(tcpHeader->getTag<SkbInfo>());
//                }
            }
            else
                EV_DETAIL << "Received SACK below total cumulative ACK snd_una=" << state->snd_una << "\n";
        }
        state->rcv_sacks += n; // total counter, no current number

        emit(rcvSacksSignal, state->rcv_sacks);

        // update scoreboard
        state->sackedBytes_old = state->sackedBytes; // needed for RFC 3042 to check if last dupAck contained new sack information
        state->sackedBytes = rexmitQueue->getTotalAmountOfSackedBytes();
        //rexmitQueue->updateLost(rexmitQueue->getHighestSackedSeqNum());

        emit(sackedBytesSignal, state->sackedBytes);
    }
    return true;
}

TcpHeader BbrConnection::addSacks(const Ptr<TcpHeader>& tcpHeader)
{
    B options_len = B(0);
    B used_options_len = tcpHeader->getHeaderOptionArrayLength();
    bool dsack_inserted = false; // set if dsack is subsets of a bigger sack block recently reported

    uint32_t start = state->start_seqno;
    uint32_t end = state->end_seqno;

    // delete old sacks (below rcv_nxt), delete duplicates and print previous status of sacks_array:
    auto it = state->sacks_array.begin();
    EV_INFO << "Previous status of sacks_array: \n" << ((it != state->sacks_array.end()) ? "" : "\t EMPTY\n");

    while (it != state->sacks_array.end()) {
        if (seqLE(it->getEnd(), state->rcv_nxt) || it->empty()) {
            EV_DETAIL << "\t SACK in sacks_array: " << " " << it->str() << " delete now\n";
            it = state->sacks_array.erase(it);
        }
        else {
            EV_DETAIL << "\t SACK in sacks_array: " << " " << it->str() << endl;

            ASSERT(seqGE(it->getStart(), state->rcv_nxt));

            it++;
        }
    }

    if (used_options_len > TCP_OPTIONS_MAX_SIZE - TCP_OPTION_SACK_MIN_SIZE) {
        EV_ERROR << "ERROR: Failed to addSacks - at least 10 free bytes needed for SACK - used_options_len=" << used_options_len << endl;

        // reset flags:
        state->snd_sack = false;
        state->snd_dsack = false;
        state->start_seqno = 0;
        state->end_seqno = 0;
        return *tcpHeader;
    }

    if (start != end) {
        if (state->snd_dsack) { // SequenceNo < rcv_nxt
            // RFC 2883, page 3:
            // "(3) The left edge of the D-SACK block specifies the first sequence
            // number of the duplicate contiguous sequence, and the right edge of
            // the D-SACK block specifies the sequence number immediately following
            // the last sequence in the duplicate contiguous sequence."
            if (seqLess(start, state->rcv_nxt) && seqLess(state->rcv_nxt, end))
                end = state->rcv_nxt;

            dsack_inserted = true;
            Sack nSack(start, end);
            state->sacks_array.push_front(nSack);
            EV_DETAIL << "inserted DSACK entry: " << nSack.str() << "\n";
        }
        else {
            uint32_t contStart = receiveQueue->getLE(start);
            uint32_t contEnd = receiveQueue->getRE(end);

            Sack newSack(contStart, contEnd);
            state->sacks_array.push_front(newSack);
            EV_DETAIL << "Inserted SACK entry: " << newSack.str() << "\n";
        }

        // RFC 2883, page 3:
        // "(3) The left edge of the D-SACK block specifies the first sequence
        // number of the duplicate contiguous sequence, and the right edge of
        // the D-SACK block specifies the sequence number immediately following
        // the last sequence in the duplicate contiguous sequence."

        // RFC 2018, page 4:
        // "* The first SACK block (i.e., the one immediately following the
        // kind and length fields in the option) MUST specify the contiguous
        // block of data containing the segment which triggered this ACK,
        // unless that segment advanced the Acknowledgment Number field in
        // the header.  This assures that the ACK with the SACK option
        // reflects the most recent change in the data receiver's buffer
        // queue."

        // RFC 2018, page 4:
        // "* The first SACK block (i.e., the one immediately following the
        // kind and length fields in the option) MUST specify the contiguous
        // block of data containing the segment which triggered this ACK,"

        // RFC 2883, page 3:
        // "(4) If the D-SACK block reports a duplicate contiguous sequence from
        // a (possibly larger) block of data in the receiver's data queue above
        // the cumulative acknowledgement, then the second SACK block in that
        // SACK option should specify that (possibly larger) block of data.
        //
        // (5) Following the SACK blocks described above for reporting duplicate
        // segments, additional SACK blocks can be used for reporting additional
        // blocks of data, as specified in RFC 2018."

        // RFC 2018, page 4:
        // "* The SACK option SHOULD be filled out by repeating the most
        // recently reported SACK blocks (based on first SACK blocks in
        // previous SACK options) that are not subsets of a SACK block
        // already included in the SACK option being constructed."

        it = state->sacks_array.begin();
        if (dsack_inserted)
            it++;

        for (; it != state->sacks_array.end(); it++) {
            ASSERT(!it->empty());

            auto it2 = it;
            it2++;
            while (it2 != state->sacks_array.end()) {
                if (it->contains(*it2)) {
                    EV_DETAIL << "sack matched, delete contained : a=" << it->str() << ", b=" << it2->str() << endl;
                    it2 = state->sacks_array.erase(it2);
                }
                else
                    it2++;
            }
        }
    }

    uint n = state->sacks_array.size();

    uint maxnode = ((B(TCP_OPTIONS_MAX_SIZE - used_options_len).get()) - 2) / 8; // 2: option header, 8: size of one sack entry

    if (n > maxnode)
        n = maxnode;

    if (n == 0) {
        if (dsack_inserted)
            state->sacks_array.pop_front(); // delete DSACK entry

        // reset flags:
        state->snd_sack = false;
        state->snd_dsack = false;
        state->start_seqno = 0;
        state->end_seqno = 0;

        return *tcpHeader;
    }

    uint optArrSize = tcpHeader->getHeaderOptionArraySize();

    uint optArrSizeAligned = optArrSize;

    while (B(used_options_len).get() % 4 != 2) {
        used_options_len++;
        optArrSizeAligned++;
    }

    while (optArrSize < optArrSizeAligned) {
        tcpHeader->appendHeaderOption(new TcpOptionNop());
        optArrSize++;
    }

    ASSERT(B(used_options_len).get() % 4 == 2);

    TcpOptionSack *option = new TcpOptionSack();
    option->setLength(8 * n + 2);
    option->setSackItemArraySize(n);

    // write sacks from sacks_array to options
    uint counter = 0;

    for (it = state->sacks_array.begin(); it != state->sacks_array.end() && counter < n; it++) {
        ASSERT(it->getStart() != it->getEnd());
        option->setSackItem(counter++, *it);
    }

    // independent of "n" we always need 2 padding bytes (NOP) to make: (used_options_len % 4 == 0)
    options_len = used_options_len + TCP_OPTION_SACK_ENTRY_SIZE * n + TCP_OPTION_HEAD_SIZE; // 8 bytes for each SACK (n) + 2 bytes for kind&length

    ASSERT(options_len <= TCP_OPTIONS_MAX_SIZE); // Options length allowed? - maximum: 40 Bytes

    tcpHeader->appendHeaderOption(option);
    tcpHeader->setHeaderLength(TCP_MIN_HEADER_LENGTH + tcpHeader->getHeaderOptionArrayLength());
    tcpHeader->setChunkLength(tcpHeader->getHeaderLength());
    // update number of sent sacks
    state->snd_sacks += n;

    emit(sndSacksSignal, state->snd_sacks);

    EV_INFO << n << " SACK(s) added to header:\n";

    for (uint t = 0; t < n; t++) {
        EV_INFO << t << ". SACK:" << " [" << option->getSackItem(t).getStart() << ".." << option->getSackItem(t).getEnd() << ")";

        if (t == 0) {
            if (state->snd_dsack)
                EV_INFO << " (D-SACK)";
            else if (seqLE(option->getSackItem(t).getEnd(), state->rcv_nxt)) {
                EV_INFO << " (received segment filled out a gap)";
                state->snd_dsack = true; // Note: Set snd_dsack to delete first sack from sacks_array
            }
        }

        EV_INFO << endl;
    }

    // RFC 2883, page 3:
    // "(1) A D-SACK block is only used to report a duplicate contiguous
    // sequence of data received by the receiver in the most recent packet.
    //
    // (2) Each duplicate contiguous sequence of data received is reported
    // in at most one D-SACK block.  (I.e., the receiver sends two identical
    // D-SACK blocks in subsequent packets only if the receiver receives two
    // duplicate segments.)//
    //
    // In case of d-sack: delete first sack (d-sack) and move old sacks by one to the left
    if (dsack_inserted)
        state->sacks_array.pop_front(); // delete DSACK entry

    // reset flags:
    state->snd_sack = false;
    state->snd_dsack = false;
    state->start_seqno = 0;
    state->end_seqno = 0;

    return *tcpHeader;
}

}
}
