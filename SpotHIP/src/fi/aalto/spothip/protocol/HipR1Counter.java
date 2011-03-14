//
// HipR1Counter - R1_COUNTER parameter
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

package fi.aalto.spothip.protocol;

public class HipR1Counter extends HipParameter {
    private long counter;

    public short getType() {
        return HipParameter.R1_COUNTER;
    }

    public int getContentLength() {
        return 12;
    }

    public byte[] getContents() {
        byte[] ret = new byte[getContentLength()];
        ret[4] = (byte) ((counter>>56)&0xff);
        ret[5] = (byte) ((counter>>48)&0xff);
        ret[6] = (byte) ((counter>>40)&0xff);
        ret[7] = (byte) ((counter>>32)&0xff);
        ret[8] = (byte) ((counter>>24)&0xff);
        ret[9] = (byte) ((counter>>16)&0xff);
        ret[10] = (byte) ((counter>>8)&0xff);
        ret[11] = (byte) (counter&0xff);
        return ret;
    }
}
