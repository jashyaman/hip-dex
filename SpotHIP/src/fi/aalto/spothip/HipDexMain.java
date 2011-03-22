//
// HipDexMain
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

import fi.aalto.spothip.crypto.HipDexPuzzleUtil;
import fi.aalto.spothip.protocol.HipPacket;

import com.sun.spot.util.IEEEAddress;

import com.sun.spot.security.*;
import com.sun.spot.security.implementation.*;
import javax.microedition.io.*;
import java.io.*;

import java.util.*;

public class HipDexMain implements Runnable, IHipDexConnectionDelegate {
    private static final int PUZZLE_REGENERATION_TIME = 120*1000;
    private static final int RETRANSMISSION_TIME = 500;
    private static final int HIP_PORT = 123;

    private Thread mainThread = null;
    private volatile boolean running = false;
    
    private Timer puzzleRegenerationTimer = null;
    private Timer retransmissionTimer = null;

    private HipDexPuzzleUtil puzzleUtil = new HipDexPuzzleUtil();
    private ECPrivateKeyImpl privateKey = null;
    private ECPublicKeyImpl publicKey = null;
    private byte[] ourHit = new byte[16];

    private boolean listening;
    private DatagramConnection connection = null;
    private Datagram incomingDatagram = null;
    private Datagram outgoingDatagram = null;

    private Hashtable connections = new Hashtable();
    private int connectionsRequiringRetransmission = 0;


    public HipDexMain(boolean listen) {
        listening = listen;

        try {
            // Create objects containing the private and public keys of Alice and Bob
            int curveType = ECKeyImpl.SECP160R1;
            privateKey = new ECPrivateKeyImpl(curveType);
            publicKey = new ECPublicKeyImpl(curveType);
            ECKeyImpl.genKeyPair(publicKey, privateKey);
        }
        catch (InvalidKeyException ike) {}
        catch (NoSuchAlgorithmException nsae) {}
   }

    public synchronized void start() throws IOException {
        if (running)
            return;
        
        connection = (DatagramConnection) Connector.open("radiogram://:" + HIP_PORT);
        incomingDatagram = connection.newDatagram(connection.getMaximumLength());
        outgoingDatagram = connection.newDatagram(connection.getMaximumLength());

        mainThread = new Thread(this);
        mainThread.start();
        
        puzzleRegenerationTimer = new Timer();
        puzzleRegenerationTimer.scheduleAtFixedRate(new PuzzleRegenerationTimerTask(), PUZZLE_REGENERATION_TIME, PUZZLE_REGENERATION_TIME);

        // XXX: Remove this from here
        HipDexConnection conn = new HipDexConnection(privateKey, publicKey, puzzleUtil, ourHit, this);
        byte[] dest = new byte[16];
        connections.put(dest, conn);
        conn.connectToHost(ourHit);

        running = true;
    }

    public void run() {
        try {
            while (running) {
                incomingDatagram.reset();
                connection.receive(incomingDatagram);
                String senderString = incomingDatagram.getAddress();
                System.out.println("Received packet from: " + senderString);

                // Get the connection that should process the packet
                HipDexConnection conn = (HipDexConnection)connections.get(senderString);
                if (conn == null) {
                    if (!listening)
                        continue;
                    conn = new HipDexConnection(privateKey, publicKey, puzzleUtil, ourHit, this);
                    connections.put(senderString, conn);
                }

                HipPacket packet = HipPacket.parse(incomingDatagram.getData(), incomingDatagram.getOffset(), incomingDatagram.getLength());
                IEEEAddress sender = new IEEEAddress(senderString);
                conn.handlePacket(packet, sender);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    public synchronized void sendPacket(HipPacket packet) throws IOException {
        System.out.println("Requesting to send packet");

        outgoingDatagram.reset();
        outgoingDatagram.write(packet.getBytes());
        connection.send(outgoingDatagram);
    }

    public synchronized void stop() throws IOException, InterruptedException {
        if (!running)
            return;

        running = false;

        // First cancel all the timers
        puzzleRegenerationTimer.cancel();
        puzzleRegenerationTimer = null;
        if (retransmissionTimer != null) {
            retransmissionTimer.cancel();
            retransmissionTimer = null;
        }

        // Close connection and join main thread
        connection.close();
        connection = null;
        incomingDatagram = null;
        outgoingDatagram = null;

        mainThread.join();
        mainThread = null;
    }

    public synchronized void signalStartRetransmission() {
        connectionsRequiringRetransmission++;
        if (retransmissionTimer == null) {
            retransmissionTimer = new Timer();
            retransmissionTimer.scheduleAtFixedRate(new RetransmissionTimerTask(), RETRANSMISSION_TIME, RETRANSMISSION_TIME);
        }
    }

    public synchronized void signalStopRetransmission() {
        connectionsRequiringRetransmission--;
        if (connectionsRequiringRetransmission == 0 && retransmissionTimer != null) {
            retransmissionTimer.cancel();
            retransmissionTimer = null;
        }
    }

    private class PuzzleRegenerationTimerTask extends TimerTask {
        public void run() {
            puzzleUtil.regenerateRandom();
        }
    }

    private class RetransmissionTimerTask extends TimerTask {
        public void run() {
            Enumeration conns = connections.elements();
            while (conns.hasMoreElements()) {
                HipDexConnection conn = (HipDexConnection)conns.nextElement();
                conn.retransmitLastPacket();
            }
        }
    }
}
