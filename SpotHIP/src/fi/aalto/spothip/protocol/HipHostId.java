//
// HipHostId - HOST_ID parameter
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

public class HipHostId extends HipParameter {
    public byte[] hi = new byte[0];
    public byte diType;
    public byte[] di = new byte[0];

    public short getType() {
        return HipParameter.HOST_ID;
    }

    public int getContentLength() {
        return 4+hi.length+di.length;
    }

    public byte[] getContents() {
        byte[] ret = new byte[getContentLength()];
        ret[0] = (byte) ((hi.length>>8)&0xff);
        ret[1] = (byte) (hi.length&0xff);
        ret[2] = (byte) (((diType<<4)&0xf0) + ((di.length>>8)&0x0f));
        ret[3] = (byte) (di.length%0xff);
        System.arraycopy(hi, 0, ret, 4, hi.length);
        System.arraycopy(di, 0, ret, 4+hi.length, di.length);
        return ret;
    }
}
