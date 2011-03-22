//
// HipPacket - Parent class for all HIP packets
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

import fi.aalto.spothip.crypto.AesCmac;
import fi.aalto.spothip.protocol.HipHipMac3;

import com.sun.spot.security.*;
import com.sun.spot.security.implementation.*;
import com.sun.spotx.crypto.spec.SecretKeySpec;

import java.util.Vector;

public abstract class HipPacket {
    public static final byte TYPE_I1 = 0x01;
    public static final byte TYPE_R1 = 0x02;
    public static final byte TYPE_I2 = 0x03;
    public static final byte TYPE_R2 = 0x04;
    public static final byte TYPE_UPDATE = 0x10;
    public static final byte TYPE_NOTIFY = 0x11;
    public static final byte TYPE_CLOSE = 0x12;
    public static final byte TYPE_CLOSE_ACK = 0x13;

    public static final byte IPPROTO_NONE = 59;

    private static final int HIP_HEADER_LENGTH = 40;

    private byte nextHeader;
    private byte packetType;
    private byte hipVersion;
    private short controls;

    private byte[] senderHit = new byte[16];
    private byte[] receiverHit = new byte[16];

    private Vector hipParameters = new Vector();

    protected HipPacket(byte type) {
        nextHeader = IPPROTO_NONE;
        packetType = type;
        hipVersion = 2;
    }

    public byte getType() {
        return packetType;
    }

    public void setSenderHit(byte[] hit) {
        System.arraycopy(hit, 0, senderHit, 0, senderHit.length);
    }

    public byte[] getSenderHit() {
        return senderHit;
    }

    public void setReceiverHit(byte[] hit) {
        System.arraycopy(hit, 0, receiverHit, 0, receiverHit.length);
    }

    public byte[] getReceiverHit() {
        return receiverHit;
    }

    public void addParameter(HipParameter parameter) {
        hipParameters.addElement(parameter);
    }

    public void recalculateCmac(byte[] cmacKey) throws InvalidKeyException {
        HipHipMac3 hipMac = (HipHipMac3)getParameter(HipParameter.HIP_MAC_3);
        if (hipMac == null) return;

        int parametersLength = 0;
        for (int i=0; i<hipParameters.size(); i++) {
            HipParameter param = (HipParameter)hipParameters.elementAt(i);
            if (param.getType() >= HipParameter.HIP_MAC_3)
                continue;

            // RFC5201-bis Section 5.2.1. TLV Format
            int Length = param.getContentLength();
            parametersLength += 11 + Length - (Length + 3) % 8;
        }
        if (parametersLength > 2008) {
            // TODO: Too large parameters length, should fail
        }

        AesCmac aesCmac = null;
         try {
            SecretKeySpec keySpec = new SecretKeySpec(cmacKey, 0, cmacKey.length, "AES");
            
            aesCmac = new AesCmac();
            aesCmac.init(keySpec);
        } catch (NoSuchAlgorithmException nsae) {}
        aesCmac.updateByte(nextHeader);
        aesCmac.updateByte((byte) ((HIP_HEADER_LENGTH+parametersLength-8)/8));
        aesCmac.updateByte(packetType);
        aesCmac.updateShort((short)0);
        aesCmac.updateShort(controls);
        aesCmac.updateBlock(senderHit);
        aesCmac.updateBlock(receiverHit);
        for (int i=0; i<hipParameters.size(); i++) {
            HipParameter param = (HipParameter)hipParameters.elementAt(i);
            if (param.getType() >= HipParameter.HIP_MAC_3)
                continue;
            aesCmac.updateBlock(param.getBytes());
        }
        byte[] cmac = aesCmac.doFinal();
        hipMac.setCmac(cmac);
   }

    public HipParameter getParameter(short type) {
        for (int i=0; i<hipParameters.size(); i++) {
            HipParameter param = (HipParameter)hipParameters.elementAt(i);
            if (param.getType() == type)
                return param;
        }
        return null;
    }

    private short calculateChecksum(byte[] data) {
        int checksum = 0;
        for (int i=0; i<data.length; i++) {
            checksum += (i%2==0) ? data[i]<<8 : data[i];
        }
        while (checksum>>16 != 0) {
            checksum = (checksum&0xffff)+(checksum>>16);
        }
        return (short)(~checksum);
    }

    public byte[] getBytes() {
        int parametersLength = 0;
        for (int i=0; i<hipParameters.size(); i++) {
            HipParameter param = (HipParameter)hipParameters.elementAt(i);

            // RFC5201-bis Section 5.2.1. TLV Format
            int Length = param.getContentLength();
            parametersLength += 11 + Length - (Length + 3) % 8;
        }
        if (parametersLength > 2008) {
            // TODO: Too large parameters length, should fail
        }

        byte[] ret = new byte[HIP_HEADER_LENGTH + parametersLength];
        ret[0] = nextHeader;
        ret[1] = (byte) ((ret.length-8)/8);
        ret[2] = (byte) (packetType&0x7f);
        ret[3] = (byte) (((hipVersion&0x0f)<<4)|0x01);
        // 2 bytes checksum
        ret[6] = (byte) (controls>>8);
        ret[7] = (byte) (controls);

        int currentIdx = 8;
        System.arraycopy(senderHit, 0, ret, currentIdx, senderHit.length);
        currentIdx += senderHit.length;
        System.arraycopy(receiverHit, 0, ret, currentIdx, receiverHit.length);
        currentIdx += receiverHit.length;
        for (int i=0; i<hipParameters.size(); i++) {
            HipParameter param = (HipParameter)hipParameters.elementAt(i);
            byte[] paramBytes = param.getBytes();

            System.arraycopy(paramBytes, 0, ret, currentIdx, paramBytes.length);
            currentIdx += paramBytes.length;
        }
        if (currentIdx != ret.length) {
            // TODO: Should throw an error if the lengts don't match
        }

        // Calculate checksum of the HIP packet
        short checksum = calculateChecksum(ret);
        ret[4] = (byte) (checksum>>8);
        ret[5] = (byte) (checksum);
        return ret;
    }

    public static HipPacket parse(byte[] data, int offset, int length) {
        return null;
    }
}
