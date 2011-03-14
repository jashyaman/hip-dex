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

package fi.aalto.spothip.crypto;

import com.sun.spot.util.IEEEAddress;

public class HipDexUtils {
    public static byte[] LTrunc(byte[] input, int bits) {
        if (bits == 8*input.length) {
            return input;
        }

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
}
