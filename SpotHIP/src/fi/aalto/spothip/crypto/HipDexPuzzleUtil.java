//
// HipDexPuzzleUtil - HIP DEX puzzle adapted to SunSPOT by using IEEEAddress
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

package fi.aalto.spothip.crypto;

import fi.aalto.spothip.HipDexUtils;
import com.sun.spot.peripheral.Spot;
import com.sun.spot.util.IEEEAddress;
import com.sun.squawk.util.Arrays;


import com.sun.spot.security.*;
import com.sun.spot.security.implementation.*;
import com.sun.spotx.crypto.spec.SecretKeySpec;

public class HipDexPuzzleUtil {
    private static final int RAND_LENGTH = 16; // Defined as CMAC-len

    int complexity;
    int generationCounter = 0;
    SecretKeySpec[] randoms = new SecretKeySpec[3];

    public HipDexPuzzleUtil() {
        this(8);
    }
    
    public HipDexPuzzleUtil(int puzzleComplexity) {
        complexity = puzzleComplexity;

        // Generate the first random
        regenerateRandom();
    }

    public int getComplexity() {
        return complexity;
    }

    public int getGenerationCounter() {
        return generationCounter;
    }

    public void regenerateRandom() {
        byte[] randomArray = new byte[RAND_LENGTH];

        // Copy old randoms into safe
        for (int i=randoms.length-1; i>0; i--) {
            randoms[i] = randoms[i-1];
        }

        try {
            SecureRandom secureRandom = SecureRandom.getInstance(SecureRandom.ALG_SECURE_RANDOM);
            secureRandom.generateData(randomArray, 0, randomArray.length);
            randoms[0] = new SecretKeySpec(randomArray, 0, randomArray.length, "AES");
            generationCounter++;
        } catch (NoSuchAlgorithmException nsae) {}
    }

    public byte[] calculateI(byte[] hitI, byte[] hitR, byte[] localAddress, byte[] remoteAddress) {
        AesCmac aesCmac = null;
        try {
            aesCmac = new AesCmac();
            aesCmac.init(randoms[0]);
        }
        catch (NoSuchAlgorithmException nsae) {}
        catch (InvalidKeyException ike) {}

        aesCmac.updateBlock(hitI);
        aesCmac.updateBlock(hitR);
        aesCmac.updateBlock(remoteAddress);
        aesCmac.updateBlock(localAddress);
        return aesCmac.doFinal();
    }

    public static byte[] solvePuzzle(byte[] theirI, byte[] hitI, byte[] hitR, int complexity) {
        AesCmac aesCmac = null;
        SecureRandom secureRandom = null;
        try {
            // FIXME: standard says two things about key in two places
            aesCmac = new AesCmac();
            aesCmac.init(new SecretKeySpec(theirI, 0, theirI.length, "AES"));
            secureRandom = SecureRandom.getInstance(SecureRandom.ALG_PSEUDO_RANDOM);
        }
        catch (NoSuchAlgorithmException nsae) {}
        catch (InvalidKeyException ike) {}

        byte[] solution = new byte[RAND_LENGTH];
        while (true) {
            secureRandom.generateData(solution, 0, solution.length);
            aesCmac.updateBlock(hitI);
            aesCmac.updateBlock(hitR);
            aesCmac.updateBlock(solution);
            byte[] verify = HipDexUtils.LTrunc(aesCmac.doFinal(), complexity);

            boolean verifyOk = true;
            for (int i=0; i<verify.length; i++) {
                if (verify[i] != 0) {
                    verifyOk = false;
                    break;
                }
            }
            
            if (verifyOk)
                break;
        }
        return solution;
    }

    public boolean verifyPuzzle(byte[] theirI, byte[] theirSolution, byte[] hitI, byte[] hitR, byte[] localAddress, byte[] remoteAddress) {
        byte[] ourI = calculateI(hitI, hitR, localAddress, remoteAddress);
        if (!Arrays.equals(ourI, theirI))
            return false;

        for (int i=0; i<randoms.length; i++) {
            if (randoms[i] == null)
                continue;
            
            AesCmac aesCmac = null;
            try {
                // FIXME: standard says two things about key in two places
                aesCmac = new AesCmac();
                aesCmac.init(new SecretKeySpec(ourI, 0, ourI.length, "AES"));
            }
            catch (NoSuchAlgorithmException nsae) {}
            catch (InvalidKeyException ike) {}
            
            aesCmac.updateBlock(hitI);
            aesCmac.updateBlock(hitR);
            aesCmac.updateBlock(theirSolution);
            byte[] verify = HipDexUtils.LTrunc(aesCmac.doFinal(), complexity);
            
            boolean verifyOk = true;
            for (int j=0; j<verify.length; j++) {
                if (verify[j] != 0) {
                    verifyOk = false;
                    break;
                }
            }
            if (verifyOk)
                return true;
        }
        return false;
    }
}
