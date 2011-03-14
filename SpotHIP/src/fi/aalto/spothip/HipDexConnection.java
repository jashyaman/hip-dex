//
// HipDexConnection
//
// Authors:
//      Juho Vähä-Herttua  <juhovh@iki.fi>
//
// Copyright (C) 2011  Aalto University
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//

package fi.aalto.spothip;

import fi.aalto.spothip.crypto.*;
import fi.aalto.spothip.protocol.*;

import com.sun.spot.peripheral.Spot;
import com.sun.spot.util.IEEEAddress;

import javax.microedition.io.*;
import java.io.IOException;

public class HipDexConnection {
    public static final int STATE_UNASSOCIATED  = 0x01;
    public static final int STATE_I1_SENT       = 0x02;
    public static final int STATE_I2_SENT       = 0x03;
    public static final int STATE_R2_SENT       = 0x04;
    public static final int STATE_ESTABLISHED   = 0x05;
    public static final int STATE_CLOSING       = 0x06;
    public static final int STATE_CLOSED        = 0x07;

    private int currentState;
    private HipDexPuzzleUtil puzzleUtil;
    
    private DatagramConnection connection;
    private IHipDexConnectionDelegate delegate;

    private IEEEAddress localAddress;
    private byte[] localHit;
    
    private IEEEAddress remoteAddress;
    private byte remotePort;
    private byte[] remoteHit;

    private HipDhGroupList dhGroupList = new HipDhGroupList(HipDhGroupList.DH_GROUP_ECP256);
    private byte[] keyX;
    private byte[] keyY;

    public HipDexConnection(HipDexPuzzleUtil puzzle, byte[] ourHit, IHipDexConnectionDelegate connectionDelegate) {
        currentState = STATE_UNASSOCIATED;
        puzzleUtil = puzzle;

        localAddress = new IEEEAddress(Spot.getInstance().getRadioPolicyManager().getIEEEAddress());
        delegate = connectionDelegate;

        localHit = new byte[ourHit.length];
        System.arraycopy(ourHit, 0, localHit, 0, ourHit.length);
    }

    private void changeCurrentState(int newState) {
        // Update the timer state according to currentState and newState
        if (currentState == STATE_I1_SENT || currentState == STATE_I2_SENT) {
            if (newState != STATE_I1_SENT && newState != STATE_I2_SENT) {
                // Stop the retransmission
                delegate.signalStartRetransmission();
            }
        } else {
            if (newState == STATE_I1_SENT || newState == STATE_I2_SENT) {
                // Start the retransmission
                delegate.signalStartRetransmission();
            }
        }
        currentState = newState;
    }

    public void handlePacket(HipPacket packet, IEEEAddress sender) throws IOException {
        if (currentState == STATE_UNASSOCIATED) {
            if (packet.getType() == HipPacket.TYPE_I1) {
                // Validate I1 packet, send R1 packet
                processPacket((HipPacketI1)packet, sender);
            } else if(packet.getType() == HipPacket.TYPE_I2) {
                // Validate I2 packet, send R2 packet
                if (processPacket((HipPacketI2)packet, sender)) {
                    remoteAddress = sender;
                    changeCurrentState(STATE_R2_SENT);
                }
            }
        } else if (currentState == STATE_I1_SENT) {
            if (packet.getType() == HipPacket.TYPE_R1) {
                // Validate R1 packet, send I2 packet
                if (processPacket((HipPacketR1)packet, sender)) {
                    remoteAddress = sender;
                    changeCurrentState(STATE_I2_SENT);
                }
            } else if(packet.getType() == HipPacket.TYPE_I2) {
                // Validate I1 packet, send R2 packet
                if (processPacket((HipPacketI1)packet, sender)) {
                    changeCurrentState(STATE_R2_SENT);
                }
            }
        } else if (currentState == STATE_I2_SENT) {
            if (packet.getType() == HipPacket.TYPE_I2) {
                // Validate I2 packet, send R2 packet
                if (processPacket((HipPacketI2)packet, sender)) {
                    changeCurrentState(STATE_R2_SENT);
                }
            } else if(packet.getType() == HipPacket.TYPE_R2) {
                // Validate R2 packet, send nothing
                if (processPacket((HipPacketR2)packet, sender)) {
                    changeCurrentState(STATE_ESTABLISHED);
                }
            }
        } else if (currentState == STATE_R2_SENT) {
            if (packet.getType() == HipPacket.TYPE_I2) {
                // Validate I2 packet, re-send R2 packet
                processPacket((HipPacketI2)packet, sender);
            }
        } else if (currentState == STATE_ESTABLISHED) {
            if (packet.getType() == HipPacket.TYPE_I2) {
                // Validate I2 packet, re-send R2 packet
                if (processPacket((HipPacketI2)packet, sender)) {
                    changeCurrentState(STATE_R2_SENT);
                }
            }
        } else if (currentState == STATE_CLOSING) {
            // TODO: not implemented
        } else if (currentState == STATE_CLOSED) {
            // TODO: not implemented

        }
    }

    // Host can be null in case of a broadcast
    public void connectToHost(IEEEAddress host, byte port, byte[] theirHit) throws IOException {
        if (currentState == STATE_UNASSOCIATED) {
            remoteAddress = host;
            remotePort = port;
            remoteHit = new byte[theirHit.length];
            System.arraycopy(theirHit, 0, remoteHit, 0, theirHit.length);

            if (remoteAddress != null) {
                connection = (DatagramConnection) Connector.open("radiogram://" + host.asDottedHex() + ":" + port);
            } else {
                connection = (DatagramConnection) Connector.open("radiogram://broadcast:" + port);
            }

            // Send the I1 packet
            HipPacketI1 i1Packet = new HipPacketI1(dhGroupList);
            i1Packet.setSenderHit(localHit);
            i1Packet.setReceiverHit(remoteHit);
            byte[] packetBytes = (new HipPacketI1(dhGroupList)).getBytes();
            Datagram datagram = connection.newDatagram(packetBytes, packetBytes.length);
            connection.send(datagram);

            changeCurrentState(STATE_I1_SENT);
        } else {
            throw new IOException("Connection has to be in UNASSOCIATED state");
        }
    }

    private boolean processPacket(HipPacketI1 packet, IEEEAddress sender) throws IOException {
        // No validation, just send R1
        byte[] puzzleI = puzzleUtil.calculateI(packet.getSenderHit(), packet.getReceiverHit(), sender);
        HipPuzzle puzzle = new HipPuzzle(puzzleUtil.getComplexity(), puzzleI);

        HipPacketR1 r1Packet = new HipPacketR1(puzzle, new HipHostId(), dhGroupList);
        r1Packet.setSenderHit(localHit);
        r1Packet.setReceiverHit(packet.getSenderHit());
        byte[] packetBytes = r1Packet.getBytes();
        Datagram datagram = connection.newDatagram(packetBytes, packetBytes.length);
        connection.send(datagram);
        return true;
    }

    private boolean processPacket(HipPacketR1 packet, IEEEAddress sender) throws IOException {
        // Validate DH_GROUP_LIST
        if (!dhGroupList.equals(packet.getParameter(HipParameter.DH_GROUP_LIST)))
            return false;
        
        // Generate I2
        HipPuzzle puzzle = (HipPuzzle)packet.getParameter(HipParameter.PUZZLE);
        if (puzzle == null) return false;

        byte[] solutionJ = HipDexPuzzleUtil.solvePuzzle(puzzle.getRandomI(), localHit, remoteHit, puzzle.getComplexity());
        HipSolution solution = new HipSolution(puzzle.getComplexity(), puzzle.getRandomI(), solutionJ);

        HipPacketI2 i2Packet = new HipPacketI2(solution);
        i2Packet.setSenderHit(localHit);
        i2Packet.setReceiverHit(remoteHit);
        byte[] packetBytes = i2Packet.getBytes();
        Datagram datagram = connection.newDatagram(packetBytes, packetBytes.length);
        connection.send(datagram);
        return true;
    }
    
    private boolean processPacket(HipPacketI2 packet, IEEEAddress sender) throws IOException {
        if (currentState == STATE_I2_SENT) {
            // Check if our HIT or their HIT is larger, if their HIT is larger
            // then just drop the packet, otherwise process and proceed
        }
        // Validate the puzzle solution, extract keying material, generate R2

        return false;
    }

    private boolean processPacket(HipPacketR2 packet, IEEEAddress sender) throws IOException {
        // Check the DH_GROUP_LIST, extract keying material,
        // cancel or restart handshake if DH_GROUP_LIST doesn't match
        return false;
    }
}
