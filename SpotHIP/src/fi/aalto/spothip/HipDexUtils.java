//
// HipDexUtils - Generic utils for HIP DEX implementation
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

import com.sun.spot.util.IEEEAddress;
import com.sun.spot.security.InvalidKeyException;
import com.sun.spot.security.implementation.ECPublicKeyImpl;

public class HipDexUtils {
    public static byte[] LTrunc(byte[] input, int bits) {
        if (input == null)
            return null;
        if (bits == 8*input.length)
            return input;

        byte[] ret = new byte[(bits+7)/8];
        System.arraycopy(input, 0, ret, 0, ret.length);
        if (bits < 8*ret.length) {
            // Zero out last bits one by one
            for (int i=0; i<8*ret.length-bits; i++) {
                ret[ret.length-1] &= (byte)~(1<<i);
            }
        }
        return ret;
    }

    public static byte[] addressToBytes(IEEEAddress address) {
        long longval = address.asLong();
        
        byte[] ret = new byte[8];
        for (int i=ret.length-1; i>=0; i--) {
            ret[i] = (byte)(longval&0xff);
            longval >>= 8;
        }
        return ret;
    }

    public static byte[] publicKeyToHit(ECPublicKeyImpl publicKey) {
        byte[] hit = new byte[16];
        hit[0] = 0x20;
        hit[1] = 0x01;
        hit[2] = 0x00;
        hit[3] = 0x15; // 5 = LTRUNC

        byte[] pubKey = new byte[1+2*publicKey.getECCurve().getField().getFFA().getByteSize()];
        try { publicKey.getW(pubKey, 0); } catch (InvalidKeyException ike) {}
        System.arraycopy(pubKey, 1, hit, 4, hit.length-4);
        return hit;
    }

    public static String byteArrayToString(byte[] data) {
        if (data == null)
            return null;

        String ret = "";
        for (int i=0; i<data.length; i++) {
            if (data[i]>=0 && data[i] < 16) ret += "0";
            ret += Integer.toHexString(data[i]&0xff);
        }
        return ret;
    }

    public static void printPacket(byte[] data) {
        if (data == null)
            return;

        for (int i=0; i<data.length/16; i++) {
            String idxString = Integer.toHexString(i<<8);
            for (int j=0; j<7-idxString.length(); j++)
                System.out.print("0");
            System.out.print(idxString+"0  ");

            for (int j=16*i; j<16*i+16 && j<data.length; j++) {
                if (data[j]>=0 && data[j] < 16) {
                    System.out.print("0");
                }
                System.out.print(Integer.toHexString(data[j]&0xff) + " ");
                if ((j+1)%8 == 0) {
                    System.out.print(" ");
                }
            }
            System.out.println();
        }
    }

    public static int compareHits(byte[] hitA, byte[] hitB) {
        if (hitA.length < hitB.length)
            return -1;
        if (hitA.length > hitB.length)
            return 1;

        for (int i=0; i<hitA.length; i++) {
            if (hitA[i] == hitB[i])
                continue;
            if (hitA[i] < hitB[i])
                return -1;
            if (hitA[i] > hitB[i])
                return 1;
        }
        return 0;
    }
}
