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

import com.sun.spotx.crypto.implementation.*;
import com.sun.spot.security.*;
import com.sun.spot.security.implementation.*;
import com.sun.spot.util.IEEEAddress;

import java.io.IOException;

public class HipDexConnection {
    public static final int STATE_UNASSOCIATED  = 0x01;
    public static final int STATE_I1_SENT       = 0x02;
    public static final int STATE_I2_SENT       = 0x03;
    public static final int STATE_R2_SENT       = 0x04;
    public static final int STATE_ESTABLISHED   = 0x05;
    public static final int STATE_CLOSING       = 0x06;
    public static final int STATE_CLOSED        = 0x07;


    private ECPrivateKeyImpl privateKey;
    private ECPublicKeyImpl publicKey;

    private int currentState;
    private HipDexPuzzleUtil puzzleUtil;
    private IHipDexConnectionDelegate delegate;
    private HipPacket lastPacket;

    private byte[] localHit;
    private byte[] remoteHit;

    private HipDhGroupList dhGroupList = new HipDhGroupList(HipDhGroupList.DH_GROUP_ECP160);

    private byte[] localEncryptionKey;
    private byte[] localIntegrityKey;
    private byte[] remoteEncryptionKey;
    private byte[] remoteIntegrityKey;

    private byte[] keyX;
    private byte[] keyY;

    public HipDexConnection(ECPrivateKeyImpl privKey, ECPublicKeyImpl pubKey,
            HipDexPuzzleUtil puzzle, IHipDexConnectionDelegate connectionDelegate) {
        privateKey = privKey;
        publicKey = pubKey;

        currentState = STATE_UNASSOCIATED;
        puzzleUtil = puzzle;
        delegate = connectionDelegate;

        localHit = HipDexUtils.publicKeyToHit(publicKey);
    }

    public int getCurrentState() {
        return currentState;
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

    private void sendPacket(HipPacket packet) throws IOException {
        lastPacket = packet;
        delegate.sendPacket(packet);
    }

    public void retransmitLastPacket() {
        if (currentState != STATE_I1_SENT && currentState != STATE_I2_SENT)
            return;
        if (lastPacket == null)
            return;
        System.out.println("Retransmitting last packet");
        try {
            delegate.sendPacket(lastPacket);
        } catch (IOException ioe) {}
    }

    public void handlePacket(HipPacket packet, IEEEAddress sender) throws IOException {
        System.out.println("Current state " + currentState + " packet type " + packet.getType());
        if (currentState == STATE_UNASSOCIATED) {
            if (packet.getType() == HipPacket.TYPE_I1) {
                // Validate I1 packet, send R1 packet
                processPacket((HipPacketI1)packet, sender);
            } else if(packet.getType() == HipPacket.TYPE_I2) {
                // Validate I2 packet, send R2 packet
                if (processPacket((HipPacketI2)packet, sender)) {
                    changeCurrentState(STATE_R2_SENT);
                }
            }
        } else if (currentState == STATE_I1_SENT) {
            if (packet.getType() == HipPacket.TYPE_R1) {
                // Validate R1 packet, send I2 packet
                if (processPacket((HipPacketR1)packet, sender)) {
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
    public void connectToHost(byte[] destinationHit) throws IOException {
        if (currentState == STATE_UNASSOCIATED) {
            remoteHit = new byte[destinationHit.length];
            System.arraycopy(destinationHit, 0, remoteHit, 0, destinationHit.length);

            // Send the I1 packet
            HipPacketI1 i1Packet = new HipPacketI1(dhGroupList);
            i1Packet.setSenderHit(localHit);
            i1Packet.setReceiverHit(remoteHit);
            sendPacket(i1Packet);

            changeCurrentState(STATE_I1_SENT);
        } else {
            throw new IOException("Connection has to be in UNASSOCIATED state");
        }
    }

    private boolean processPacket(HipPacketI1 packet, IEEEAddress sender) throws IOException {
        // No validation, just send R1
        byte[] puzzleI = puzzleUtil.calculateI(packet.getSenderHit(), packet.getReceiverHit(), new byte[0], new byte[0]);
        HipPuzzle puzzle = new HipPuzzle(puzzleUtil.getComplexity(), puzzleI);
        HipHostId hostId = new HipHostId(publicKey);

        HipPacketR1 r1Packet = new HipPacketR1(puzzle, hostId, dhGroupList);
        r1Packet.setSenderHit(localHit);
        r1Packet.setReceiverHit(packet.getSenderHit());
        sendPacket(r1Packet);
        return true;
    }

    private boolean processPacket(HipPacketR1 packet, IEEEAddress sender) throws IOException {
        // Validate DH_GROUP_LIST
        if (!dhGroupList.equals(packet.getParameter(HipParameter.DH_GROUP_LIST))) {
            System.out.println("Group DH list not equal");
            return false;
        }
        
        // Generate I2
        HipPuzzle puzzle = (HipPuzzle)packet.getParameter(HipParameter.PUZZLE);
        HipHostId theirHostId = (HipHostId)packet.getParameter(HipParameter.HOST_ID);
        if (puzzle == null || theirHostId == null) {
            System.out.println("Either puzzle or host id not found");
            return false;
        }

        ECPublicKeyImpl theirPublicKey = theirHostId.getPublicKey();
        if (theirPublicKey == null) {
            System.out.println("received host id not valid");
            return false;
        }

        if (!generateKeysFromPublicKey(theirPublicKey, false, packet.getSenderHit(), packet.getReceiverHit(), puzzle.getRandomI())) {
            System.out.println("Generating keys using public key failed");
            return false;
        }

        byte[] solutionJ = HipDexPuzzleUtil.solvePuzzle(puzzle.getRandomI(), localHit, remoteHit, puzzle.getComplexity());
        HipSolution solution = new HipSolution(puzzle.getComplexity(), puzzle.getRandomI(), solutionJ);
        HipHostId ourHostId = new HipHostId(publicKey);

        HipPacketI2 i2Packet = new HipPacketI2(solution, ourHostId, new HipEncryptedKey());
        i2Packet.setSenderHit(localHit);
        i2Packet.setReceiverHit(remoteHit);
        i2Packet.recalculateCmac(localIntegrityKey);
        sendPacket(i2Packet);
        return true;
    }
    
    private boolean processPacket(HipPacketI2 packet, IEEEAddress sender) throws IOException {
        if (currentState == STATE_I2_SENT) {
            // Check if our HIT or their HIT is larger, if their HIT is larger
            // then just drop the packet, otherwise process and proceed
            if (HipDexUtils.compareHits(localHit, remoteHit) < 0)
                return false;
        }
        // Validate the puzzle solution, extract keying material, generate R2
        HipSolution solution = (HipSolution)packet.getParameter(HipParameter.PUZZLE);
        HipHostId hostId = (HipHostId)packet.getParameter(HipParameter.HOST_ID);
        if (solution == null || hostId == null)
            return false;

        boolean puzzleVerified = puzzleUtil.verifyPuzzle(solution.getRandomI(), solution.getSolutionJ(), packet.getSenderHit(), packet.getReceiverHit(), new byte[0], new byte[0]);
        if (!puzzleVerified) {
            System.out.println("Puzzle didn't verify correctly");
        }
        
        // Update the remoteHit to be correct
        remoteHit = new byte[packet.getSenderHit().length];
        System.arraycopy(packet.getSenderHit(), 0, remoteHit, 0, remoteHit.length);
        
        ECPublicKeyImpl theirPublicKey = hostId.getPublicKey();
        if (theirPublicKey == null)
            return false;

        if (!generateKeysFromPublicKey(theirPublicKey, false, packet.getSenderHit(), packet.getReceiverHit(), solution.getRandomI()))
            return false;

        HipPacketR2 r2Packet = new HipPacketR2(dhGroupList, new HipEncryptedKey());
        r2Packet.setSenderHit(localHit);
        r2Packet.setReceiverHit(remoteHit);
        r2Packet.recalculateCmac(localIntegrityKey);
        sendPacket(r2Packet);
        return true;
    }

    private boolean processPacket(HipPacketR2 packet, IEEEAddress sender) throws IOException {
        // Check the DH_GROUP_LIST, extract keying material,
        // cancel or restart handshake if DH_GROUP_LIST doesn't match
        return false;
    }

    private boolean generateKeysFromPublicKey(ECPublicKeyImpl publicKey, boolean initiator, byte[] senderHit, byte[] receiverHit, byte[] randomI) {
        ECDHKeyAgreement keyAgreement = new ECDHKeyAgreement();
        try {
            byte[] pubKey = new byte[1+2*publicKey.getECCurve().getField().getFFA().getByteSize()];
            byte[] secret = new byte[(pubKey.length-1)/2];
            publicKey.getW(pubKey, 0);
          
            keyAgreement.init(privateKey);
            keyAgreement.generateSecret(pubKey, 0, pubKey.length, secret, 0);
            HipDexKeyUtil keyUtil = new HipDexKeyUtil(16, 16);
            if (initiator) {
                keyUtil.generateKeys(receiverHit, senderHit, randomI, secret);
                localEncryptionKey = keyUtil.getInitiatorEncryptionKey();
                localIntegrityKey = keyUtil.getInitiatorIntegrityKey();
                remoteEncryptionKey = keyUtil.getResponderEncryptionKey();
                remoteIntegrityKey = keyUtil.getInitiatorIntegrityKey();
            } else {
                keyUtil.generateKeys(senderHit, receiverHit, randomI, secret);
                localEncryptionKey = keyUtil.getResponderEncryptionKey();
                localIntegrityKey = keyUtil.getResponderIntegrityKey();
                remoteEncryptionKey = keyUtil.getInitiatorEncryptionKey();
                remoteIntegrityKey = keyUtil.getInitiatorIntegrityKey();
            }
        } catch (Exception e) { return false; }
        return true;
    }
}
