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

package bbr.transportlayer.bbr;

import tcppaced.transportlayer.tcp.TcpPacedConnection;

simple BbrConnection extends TcpPacedConnection
{
    parameters:
        @class("inet::tcp::BbrConnection"); 
        
        @signal[additiveIncrease];
        @signal[minRtt];
        @signal[connMinRtt];
        @signal[maxBandwidthFilter];
        @signal[state];
        @signal[pacingGain];
        
        @signal[mDelivered];
        @signal[mFirstSentTime];
        @signal[mLastSentTime];
        @signal[mbytesInFlight];
        @signal[mbytesInFlightTotal];
        @signal[mbytesLoss];
        @signal[msendElapsed];
        @signal[mackElapsed];
        @signal[targetCwnd];
        @signal[priorCwnd];
        @signal[estimatedBdp];
        @signal[roundCount];
        @signal[recover];
        @signal[lossRecovery];
        @signal[highRxt];
        @signal[txBufferLength];
        @signal[recoveryPoint];
        
        @statistic[additiveIncrease](record=vector; interpolationmode=sample-hold);
        @statistic[minRtt](record=vector; interpolationmode=sample-hold);
        @statistic[connMinRtt](record=vector; interpolationmode=sample-hold);
        @statistic[maxBandwidthFilter](record=vector; interpolationmode=sample-hold);
        @statistic[state](record=vector; interpolationmode=sample-hold);
        @statistic[pacingGain](record=vector; interpolationmode=sample-hold);
        @statistic[targetCwnd](record=vector; interpolationmode=sample-hold);
        @statistic[priorCwnd](record=vector; interpolationmode=sample-hold);
        @statistic[roundCount](record=vector; interpolationmode=sample-hold);
        @statistic[recover](record=vector; interpolationmode=sample-hold);
        @statistic[lossRecovery](record=vector; interpolationmode=sample-hold);
        @statistic[highRxt](record=vector; interpolationmode=sample-hold);
        @statistic[txBufferLength](record=vector; interpolationmode=sample-hold);
        @statistic[recoveryPoint](record=vector; interpolationmode=sample-hold);
        
        @statistic[mDelivered](record=vector; interpolationmode=sample-hold);
		@statistic[mFirstSentTime](record=vector; interpolationmode=sample-hold);
		@statistic[mLastSentTime](record=vector; interpolationmode=sample-hold);
		@statistic[msendElapsed](record=vector; interpolationmode=sample-hold);
		@statistic[mackElapsed](record=vector; interpolationmode=sample-hold);
		@statistic[mbytesInFlight](record=vector; interpolationmode=sample-hold);
		@statistic[mbytesInFlightTotal](record=vector; interpolationmode=sample-hold);
		@statistic[mbytesLoss](record=vector; interpolationmode=sample-hold);
		@statistic[estimatedBdp](record=vector; interpolationmode=sample-hold);
}
