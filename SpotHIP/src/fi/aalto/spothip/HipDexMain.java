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

    HipDexPuzzleUtil puzzleUtil = new HipDexPuzzleUtil();
    private byte[] ourHit = new byte[16];

    private boolean listening;
    DatagramConnection listeningConnection = null;
    Datagram incomingDatagram = null;

    private Hashtable connections = new Hashtable();
    private int connectionsRequiringRetransmission = 0;


    public HipDexMain(boolean listen) {
        listening = listen;
    }

    public synchronized void start() throws IOException {
        if (running)
            return;
        
        listeningConnection = (DatagramConnection) Connector.open("radiogram://:" + HIP_PORT);
        incomingDatagram = listeningConnection.newDatagram(listeningConnection.getMaximumLength());

        mainThread = new Thread(this);
        mainThread.start();
        
        puzzleRegenerationTimer = new Timer();
        puzzleRegenerationTimer.scheduleAtFixedRate(new PuzzleRegenerationTimerTask(), PUZZLE_REGENERATION_TIME, PUZZLE_REGENERATION_TIME);

        // XXX: Remove this from here
        HipDexConnection conn = new HipDexConnection(puzzleUtil, ourHit, this);
        IEEEAddress dest = new IEEEAddress("0014.4F01.0000.71D7");
        connections.put(dest.asDottedHex(), conn);
        conn.connectToHost(dest, ourHit);

        running = true;
    }

    public void run() {
        try {
            while (running) {
                incomingDatagram.reset();
                listeningConnection.receive(incomingDatagram);
                String senderString = incomingDatagram.getAddress();
                System.out.println("Received packet from: " + senderString);

                // Get the connection that should process the packet
                HipDexConnection conn = (HipDexConnection)connections.get(senderString);
                if (conn == null) {
                    if (!listening)
                        continue;
                    conn = new HipDexConnection(puzzleUtil, ourHit, this);
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

    public void sendPacket(HipPacket packet, IEEEAddress destination) {
        System.out.println("Requesting to send packet");
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
        listeningConnection.close();
        listeningConnection = null;
        incomingDatagram = null;

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
