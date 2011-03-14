//
// HipHipCipher - HIP_CIPHER parameter
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

public class HipHipCipher extends HipParameter {
    public static final short NULL_ENCRYPT = 1;
    public static final short AES_128_CBC  = 2;
    public static final short THREEDES_CBC = 3;

    public short getType() {
        return HipParameter.HIP_CIPHER;
    }

    public int getContentLength() {
        return 1;
    }

    public byte[] getContents() {
        return new byte[] { AES_128_CBC };
    }
}
