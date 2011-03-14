//
// StartApplication
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
import com.sun.spot.peripheral.Spot;
import com.sun.spot.util.*;
import com.sun.spotx.crypto.*;
import com.sun.spotx.crypto.spec.SecretKeySpec;
import com.sun.spot.security.*;

import java.io.*;
import javax.microedition.io.*;
import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;

/**
 * The startApp method of this class is called by the VM to start the
 * application.
 *
 * The manifest specifies this class as MIDlet-1, which means it will
 * be selected for execution.
 */
public class StartApplication extends MIDlet {

    protected void startApp() throws MIDletStateChangeException {
        System.out.println("Started WebClient application ...");

        // Listen for downloads/commands over USB connection
	new com.sun.spot.service.BootloaderListenerService().getInstance().start();

        System.out.println("Memory available at start: " +
                Runtime.getRuntime().freeMemory() + "/" +
                Runtime.getRuntime().totalMemory());
        
        IEEEAddress remoteAddress = new IEEEAddress(Spot.getInstance().getRadioPolicyManager().getIEEEAddress());
        byte[] hitI = new byte[16];
        byte[] hitR = new byte[16];

        // Responder does this when sending R1
        HipDexPuzzleUtil rPuzzle = new HipDexPuzzleUtil(6);
        byte[] I = rPuzzle.calculateI(hitI, hitR, remoteAddress);

        // Initiator does this when sending I2
        long startTime = System.currentTimeMillis();
        byte[] solution = HipDexPuzzleUtil.solvePuzzle(I, hitI, hitR, rPuzzle.getComplexity());
        long endTime = System.currentTimeMillis();
        System.out.println("Solved puzzle in " + (endTime-startTime) + " milliseconds");

        // Responder does this when received I2
        startTime = System.currentTimeMillis();
        boolean verified = rPuzzle.verifyPuzzle(I, solution, hitI, hitR, remoteAddress);
        endTime = System.currentTimeMillis();
        System.out.println("Verified puzzle as " + verified + " in " + (endTime-startTime) + " milliseconds");
 
        System.out.println("Memory available at end: " +
                Runtime.getRuntime().freeMemory() + "/" +
                Runtime.getRuntime().totalMemory());
    }

    protected void pauseApp() {
        // This will never be called by the Squawk VM
    }

    protected void destroyApp(boolean arg0) throws MIDletStateChangeException {
        // Only called if startApp throws any exception other than MIDletStateChangeException
    }

    private void printData(String name, byte[] data) {
        System.out.print(name + ": ");
        for (int i=0; i<data.length; i++) {
            System.out.print(Integer.toHexString(data[i]&0xff));
        }
        System.out.println();
    }
}
