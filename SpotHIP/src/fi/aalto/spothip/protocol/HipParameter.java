//
// HipParameter - Parent class for all HIP parameters
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

public abstract class HipParameter {
    public static final short R1_COUNTER      = 128;
    public static final short PUZZLE          = 257;
    public static final short SOLUTION        = 321;
    public static final short HIP_CIPHER      = 579;
    public static final short ENCRYPTED       = 641;
    public static final short HOST_ID         = 705;
    public static final short ENCRYPTED_KEY   = 643;
    public static final short HIT_SUITE_LIST  = 715;
    public static final short DH_GROUP_LIST   = 2151;

    public static final short HIP_MAC_3               = (short) 61507;
    public static final short ECHO_REQUEST_UNSIGNED   = (short) 63661;
    public static final short ECHO_RESPONSE_UNSIGNED  = (short) 63425;

    public abstract short getType();
    public abstract byte[] getContents();
    public abstract int getContentLength();
    protected abstract boolean parseContent(byte[] content);

    public byte[] getPadding() {
        return null;
    }

    public final byte[] getBytes() {
        short type = getType();
        byte[] contents = getContents();
        byte[] padding = getPadding();
        if (padding == null) {
            if (contents.length%8 == 0)
                padding = new byte[0];
            else
                padding = new byte[8-(4+contents.length)%8];
        }
        
        byte[] data = new byte[4+contents.length+padding.length];
        data[0] = (byte) ((type>>8)&0xff);
        data[1] = (byte) (type&0xff);
        data[2] = (byte) ((contents.length>>8)%0xff);
        data[3] = (byte) (contents.length&0xff);
        System.arraycopy(contents, 0, data, 4, contents.length);
        System.arraycopy(padding, 0, data, 4+contents.length, padding.length);
        return data;
    }

    public static HipParameter parse(short type, byte[] contents) {
        HipParameter param = null;
        switch (type) {
            case HipParameter.DH_GROUP_LIST:
                param = new HipDhGroupList(contents);
                break;
            case HipParameter.ECHO_REQUEST_UNSIGNED:
                break;
            case HipParameter.ECHO_RESPONSE_UNSIGNED:
                break;
            case HipParameter.ENCRYPTED:
                break;
            case HipParameter.ENCRYPTED_KEY:
                break;
            case HipParameter.HIP_CIPHER:
                break;
            case HipParameter.HIP_MAC_3:
                break;
            case HipParameter.HIT_SUITE_LIST:
                break;
            case HipParameter.HOST_ID:
                break;
            case HipParameter.PUZZLE:
                break;
            case HipParameter.R1_COUNTER:
                break;
            case HipParameter.SOLUTION:
                break;
        }
        return param;
    }
}
