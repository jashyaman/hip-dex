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

import com.sun.spot.security.InvalidKeyException;
import com.sun.spot.security.GeneralSecurityException;
import com.sun.spot.security.implementation.ECKeyImpl;
import com.sun.spot.security.implementation.ECPublicKeyImpl;

public class HipHostId extends HipParameter {
    private static final int ALGORITHM_ECDH = 11;
    private static final int CURVE_SECP160R1 = 1;
    private static final int CURVE_SECP192R1 = 2;
    private static final int CURVE_SECP224R1 = 3;

    public byte[] hi = new byte[0];
    public byte diType;
    public byte[] di = new byte[0];

    protected HipHostId() {}

    public HipHostId(ECPublicKeyImpl publicKey) {
        int bitSize = publicKey.getECCurve().getField().getBitSize();
        byte[] pubKey = new byte[1+2*publicKey.getECCurve().getField().getFFA().getByteSize()];
        try { publicKey.getW(pubKey, 0); } catch (InvalidKeyException ike) {}

        // Copy the host id to the hi array
        hi = new byte[pubKey.length+2];
        if (bitSize == 160) {
            hi[1] = CURVE_SECP160R1;
        } else if (bitSize == 192) {
            hi[1] = CURVE_SECP192R1;
        } else if (bitSize == 224) {
            hi[1] = CURVE_SECP224R1;
        }
        System.arraycopy(pubKey, 0, hi, 2, pubKey.length);
    }

    public ECPublicKeyImpl getPublicKey() {
        int curveId = 0;
        int type = ((hi[0]&0xff)<<8)|(hi[1]&0xff);
        if (type == CURVE_SECP160R1) {
            curveId = ECKeyImpl.SECP160R1;
        } else if (type == CURVE_SECP192R1) {
            curveId = ECKeyImpl.SECP192R1;
        } else if (type == CURVE_SECP224R1) {
            curveId = ECKeyImpl.SECP224R1;
        } else {
            return null;
        }
        
        byte[] pubKey = new byte[hi.length-2];
        System.arraycopy(hi, 2, pubKey, 0, pubKey.length);

        ECPublicKeyImpl publicKey = new ECPublicKeyImpl(curveId);
        try { publicKey.setW(pubKey, 0, pubKey.length); }
        catch (GeneralSecurityException gse) { return null; }
        return publicKey;
    }

    public short getType() {
        return HipParameter.HOST_ID;
    }

    public int getContentLength() {
        return 6+hi.length+di.length;
    }

    public byte[] getContents() {
        byte[] ret = new byte[getContentLength()];
        ret[0] = (byte) ((hi.length>>8)&0xff);
        ret[1] = (byte) (hi.length&0xff);
        ret[2] = (byte) (((diType<<4)&0xf0) + ((di.length>>8)&0x0f));
        ret[3] = (byte) (di.length%0xff);
        ret[4] = 0x00;
        ret[5] = ALGORITHM_ECDH;
        System.arraycopy(hi, 0, ret, 6, hi.length);
        System.arraycopy(di, 0, ret, 6+hi.length, di.length);
        return ret;
    }

    protected boolean parseContent(byte[] content) {
        if (content.length < 6)
            return false;

        int hiLength = ((content[0]&0xff)<<8)|(content[1]&0xff);
        int diLength = ((content[2]&0xff)<<8)|(content[3]&0xff);
        int algorithm = ((content[4]&0xff)<<8)|(content[5]&0xff);
        if (6+hiLength+diLength > content.length)
            return false;
        if (algorithm != ALGORITHM_ECDH)
            return false;

        hi = new byte[hiLength];
        di = new byte[diLength];
        System.arraycopy(content, 6, hi, 0, hiLength);
        System.arraycopy(content, 6+hiLength, di, 0, diLength);
        return true;
    }
}
