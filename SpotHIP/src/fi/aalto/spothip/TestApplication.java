//
// TestApplication
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
import fi.aalto.spothip.HipDexMain;

import com.sun.spot.peripheral.Spot;
import com.sun.spot.util.*;

import com.sun.spotx.crypto.*;
import com.sun.spotx.crypto.spec.SecretKeySpec;
import com.sun.spotx.crypto.implementation.ECDHKeyAgreement;
import com.sun.spot.security.*;
import com.sun.spot.security.implementation.*;

// These are only for the eccBugTest
import com.sun.spot.security.implementation.ecc.FFA;
import com.sun.spot.security.implementation.ecc.NIST160PrimeField;

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
public class TestApplication extends MIDlet {

    protected void startApp() throws MIDletStateChangeException {
        System.out.println("Started WebClient application ...");

        // Listen for downloads/commands over USB connection
	new com.sun.spot.service.BootloaderListenerService().getInstance().start();

        System.out.println("Memory available at start: " +
                Runtime.getRuntime().freeMemory() + "/" +
                Runtime.getRuntime().totalMemory());

        puzzleTest(8);
        ecdhTest(ECKeyImpl.SECP160R1);
        ecdhTest(ECKeyImpl.SECP192R1);
        ecdhTest(ECKeyImpl.SECP224R1);
        eccBugTest();

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


    private void puzzleTest(int complexity) {
        IEEEAddress remoteAddress = new IEEEAddress(Spot.getInstance().getRadioPolicyManager().getIEEEAddress());
        byte[] hitI = new byte[16];
        byte[] hitR = new byte[16];

        // Responder does this when sending R1
        HipDexPuzzleUtil rPuzzle = new HipDexPuzzleUtil(complexity);
        byte[] I = rPuzzle.calculateI(hitI, hitR, new byte[0], new byte[0]);

        // Initiator does this when sending I2
        long startTime = System.currentTimeMillis();
        byte[] solution = HipDexPuzzleUtil.solvePuzzle(I, hitI, hitR, rPuzzle.getComplexity());
        long endTime = System.currentTimeMillis();
        System.out.println("Solved puzzle in " + (endTime-startTime) + " milliseconds");

        // Responder does this when received I2
        startTime = System.currentTimeMillis();
        boolean verified = rPuzzle.verifyPuzzle(I, solution, hitI, hitR, new byte[0], new byte[0]);
        endTime = System.currentTimeMillis();
        System.out.println("Verified puzzle as " + verified + " in " + (endTime-startTime) + " milliseconds");
   }

    private void ecdhTest(int curveType) {
        // Create key agreements for both Alice and Bob
        ECDHKeyAgreement keyAgreementAlice = new ECDHKeyAgreement();
        ECDHKeyAgreement keyAgreementBob = new ECDHKeyAgreement();

        // Create byte arrays for public keys of Alice and bob
        byte[] publicAlice = new byte[0];
        byte[] publicBob = new byte[0];
        int publicAliceLength=0, publicBobLength=0;

        int keySizeBytes=0;
        try {
            // Create objects containing the private and public keys of Alice and Bob
            ECPrivateKeyImpl privateKeyAlice = new ECPrivateKeyImpl(curveType);
            ECPublicKeyImpl publicKeyAlice = new ECPublicKeyImpl(curveType);
            ECPrivateKeyImpl privateKeyBob = new ECPrivateKeyImpl(curveType);
            ECPublicKeyImpl publicKeyBob = new ECPublicKeyImpl(curveType);

            keySizeBytes = privateKeyAlice.getECCurve().getField().getFFA().getByteSize();
            publicAlice = new byte[1+2*keySizeBytes];
            publicBob = new byte[1+2*keySizeBytes];

            // Generate the actual private and public keys into the objects
            System.out.println("Generating two ECDH key pairs");
            long startTime = System.currentTimeMillis();
            ECKeyImpl.genKeyPair(publicKeyAlice, privateKeyAlice);
            ECKeyImpl.genKeyPair(publicKeyBob, privateKeyBob);
            long endTime = System.currentTimeMillis();
            System.out.println("Generating two key pairs took " + (endTime-startTime) + " milliseconds");

            // Initialize the key agreements by using private keys
            keyAgreementAlice.init(privateKeyAlice);
            keyAgreementBob.init(privateKeyBob);

            // Serialize the public keys of Alice and Bob into the byte arrays
            publicAliceLength = publicKeyAlice.getW(publicAlice, 0);
            publicBobLength = publicKeyBob.getW(publicBob, 0);
        }
        catch (InvalidKeyException ike) {}
        catch (NoSuchAlgorithmException nsae) {}

        // Create byte arrays for the ECDH secrets of Alice and Bob
        byte[] secretAlice = new byte[keySizeBytes];
        byte[] secretBob = new byte[keySizeBytes];
        int secretAliceLength=0, secretBobLength=0;

        try {
            // Calculate the actual ECDH secrets by using the key agreements and public keys
            System.out.println("Calculating two ECDH secrets");
            long startTime = System.currentTimeMillis();
            secretAliceLength = keyAgreementAlice.generateSecret(publicBob, 0, publicBobLength, secretAlice, 0);
            secretBobLength = keyAgreementBob.generateSecret(publicAlice, 0, publicAliceLength, secretBob, 0);
            long endTime = System.currentTimeMillis();
            System.out.println("Calculating two secrets took " + (endTime-startTime) + " milliseconds");
            printData("secretAlice", secretAlice);
            printData("secretBob", secretBob);
        }
        catch (GeneralSecurityException gse) {}
    }

    private void eccBugTest() {
        FFA ffa = new FFA(160);
        NIST160PrimeField pf = new NIST160PrimeField(ffa);

        // Construct a as something a little bit larger than P, for example P+1
        int[] a = new int[] { 0x00000000, 0x0ffffff8, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x000fffff };
        int[] b = ffa.from("1");
        int[] r = ffa.acquireVar();

        // Multiply a and b
        pf.multiply(r, a, b);
        System.out.println("Reduction was successful: " + (r[5] < 0x000fffff));
    }
}