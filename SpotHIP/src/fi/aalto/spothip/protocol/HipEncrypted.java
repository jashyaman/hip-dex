//
// HipEncrypted - ENCRYPTED parameter
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

public class HipEncrypted extends HipParameter {
    private final static int IV_LENGTH = 16;

    private byte[] iv = new byte[IV_LENGTH];
    private byte[] encryptedData = new byte[0];

    public short getType() {
        return HipParameter.ENCRYPTED;
    }

    public int getContentLength() {
        return 4+iv.length+encryptedData.length;
    }

    public byte[] getContents() {
        byte[] ret = new byte[getContentLength()];
        System.arraycopy(iv, 0, ret, 4, iv.length);
        System.arraycopy(encryptedData, 0, ret, 4+iv.length, encryptedData.length);
        return ret;
    }

    protected boolean parseContent(byte[] content) {
        System.arraycopy(content, 4, iv, 0, IV_LENGTH);
        encryptedData = new byte[content.length-4-IV_LENGTH];
        System.arraycopy(content, 4+IV_LENGTH, encryptedData, 0, encryptedData.length);
        return true;
    }
}
