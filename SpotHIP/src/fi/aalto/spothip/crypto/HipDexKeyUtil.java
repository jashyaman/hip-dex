//
// HipDexKeyUtil - HIP DEX key generation utils using AES-128 CMAC
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
import com.sun.spotx.crypto.spec.SecretKeySpec;

public class HipDexKeyUtil {
    private byte[] iEncryptionKey;
    private byte[] iIntegrityKey;
    private byte[] rEncryptionKey;
    private byte[] rIntegrityKey;

    public HipDexKeyUtil(int encryptionKeyLength, int integrityKeyLength) {
        iEncryptionKey = new byte[encryptionKeyLength];
        rEncryptionKey = new byte[encryptionKeyLength];
        iIntegrityKey = new byte[integrityKeyLength];
        rIntegrityKey = new byte[integrityKeyLength];
    }

    public final byte[] getInitiatorEncryptionKey() {
        return iEncryptionKey;
    }

    public final byte[] getInitiatorIntegrityKey() {
        return iIntegrityKey;
    }

    public final byte[] getResponderEncryptionKey() {
        return rEncryptionKey;
    }

    public final byte[] getResponderIntegrityKey() {
        return rIntegrityKey;
    }

    public final void generateKeys(byte[] hitI, byte[] hitR, byte[] iarr, byte[] input) throws Exception {
        if (hitI.length != 16 || hitR.length != 16)
            throw new Exception("HIT length invalid, must be 128 bits");
        if (iarr.length != 16)
            throw new Exception("I length invalid, must be 128 bits (AES block size)");

        AesCmac aesCmac = null;
        SecretKeySpec iKey = null;
        try {
            aesCmac = new AesCmac();
            iKey = new SecretKeySpec(iarr, 0, iarr.length, "AES");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // Check which HIT is greater
        boolean iGreater = (HipDexUtils.compareHits(hitI, hitR) > 0);

        // Combine the hits to byte array, smaller first
        byte[] hitsCombined = new byte[32];
        if (iGreater) {
            System.arraycopy(hitR, 0, hitsCombined, 0, 16);
            System.arraycopy(hitI, 0, hitsCombined, 16, 16);
        } else {
            System.arraycopy(hitI, 0, hitsCombined, 0, 16);
            System.arraycopy(hitR, 0, hitsCombined, 16, 16);
        }

        // Perform CKDF extract, results in key data ck
        byte[] extractString = "CKDF-Extract".getBytes();
        aesCmac.init(iKey);
        aesCmac.updateBlock(input);
        aesCmac.updateBlock(hitsCombined);
        aesCmac.updateBlock(extractString);
        byte[] ckarr = aesCmac.doFinal();

        // Create secret key from the ck data
        SecretKeySpec ckKey = null;
        try {
            ckKey = new SecretKeySpec(ckarr, 0, ckarr.length, "AES");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // Expand key material from the ck
        byte[] expandString = "CKDF-Expand".getBytes();
        byte[] keymat = new byte[2*iEncryptionKey.length + 2*iIntegrityKey.length];
        int keymatOffset = 0;
        
        byte[] T = new byte[0];
        aesCmac.init(ckKey);
        for (int i=1; keymatOffset < keymat.length; i++) {
            aesCmac.updateBlock(T);
            aesCmac.updateBlock(expandString);
            aesCmac.updateByte((byte)i);
            T = aesCmac.doFinal();
            if (T.length < keymat.length-keymatOffset) {
                System.arraycopy(T, 0, keymat, keymatOffset, T.length);
                keymatOffset += T.length;
            } else {
                System.arraycopy(T, 0, keymat, keymatOffset, keymat.length-keymatOffset);
                keymatOffset = keymat.length;
            }
        }

        // Copy key material into correct key arrays
        if (iGreater) {
            System.arraycopy(keymat, 0, iEncryptionKey, 0, iEncryptionKey.length);
            System.arraycopy(keymat, iEncryptionKey.length, iIntegrityKey, 0, iIntegrityKey.length);
            System.arraycopy(keymat, iEncryptionKey.length+iIntegrityKey.length, rEncryptionKey, 0, rEncryptionKey.length);
            System.arraycopy(keymat, iEncryptionKey.length+iIntegrityKey.length+rEncryptionKey.length, rIntegrityKey, 0, rIntegrityKey.length);
        } else {
            System.arraycopy(keymat, 0, rEncryptionKey, 0, rEncryptionKey.length);
            System.arraycopy(keymat, rEncryptionKey.length, rIntegrityKey, 0, rIntegrityKey.length);
            System.arraycopy(keymat, rEncryptionKey.length+rIntegrityKey.length, iEncryptionKey, 0, iEncryptionKey.length);
            System.arraycopy(keymat, rEncryptionKey.length+rIntegrityKey.length+iEncryptionKey.length, iIntegrityKey, 0, iIntegrityKey.length);
        }
    }
}
