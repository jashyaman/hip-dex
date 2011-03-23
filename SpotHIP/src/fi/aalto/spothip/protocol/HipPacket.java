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
import fi.aalto.spothip.HipDexUtils;

import com.sun.spot.security.*;
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

    private byte[] calculateCmac(byte[] cmacKey) {
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
        } catch (Exception e) { return null; }
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
        return aesCmac.doFinal();
    }

    public boolean verifyCmac(byte[] cmacKey) {
        HipHipMac3 hipMac = (HipHipMac3)getParameter(HipParameter.HIP_MAC_3);
        if (hipMac == null) return false;

        byte[] cmac = calculateCmac(cmacKey);
        return com.sun.squawk.util.Arrays.equals(hipMac.getContents(), cmac);
   }

    public void recalculateCmac(byte[] cmacKey) {
        HipHipMac3 hipMac = (HipHipMac3)getParameter(HipParameter.HIP_MAC_3);
        if (hipMac == null) return;

        byte[] cmac = calculateCmac(cmacKey);
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

    private static short calculateChecksum(byte[] data) {
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
        System.arraycopy(senderHit, 0, ret, currentIdx, 16);
        currentIdx += 16;
        System.arraycopy(receiverHit, 0, ret, currentIdx, 16);
        currentIdx += 16;
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
        ret[4] = (byte)(checksum>>8);
        ret[5] = (byte)(checksum);
        return ret;
    }

    public static HipPacket parse(byte[] data, int offset, int length) {
        if (data == null)
            return null;
        if ((data.length - offset) < length)
            return null;
        if (length < 8)
            return null;
        int packetLength = 8+(data[offset+1]&0xff)*8;
        if (packetLength < 40 || packetLength > length)
            return null;

        // Construct the actual packet data array
        byte[] packetData = new byte[packetLength];
        System.arraycopy(data, offset, packetData, 0, packetLength);

        // Calculate checksum and confirm it is correct
        short checksum = (short)(((packetData[4]&0xff)<<8)|(packetData[5]&0xff));
        packetData[4] = 0; packetData[5] = 0;
        if (checksum != calculateChecksum(packetData))
            return null;

        HipPacket packet = null;
        byte packetType = (byte)(packetData[2]&0x7f);
        switch (packetType) {
            case HipPacket.TYPE_I1:
                packet = new HipPacketI1();
                break;
            case HipPacket.TYPE_R1:
                packet = new HipPacketR1();
                break;
            case HipPacket.TYPE_I2:
                packet = new HipPacketI2();
                break;
            case HipPacket.TYPE_R2:
                packet = new HipPacketR2();
                break;
        }
        packet.nextHeader = packetData[0];
        packet.hipVersion = (byte)((packetData[3]>>4)&0x0f);
        packet.controls = (short)(((packetData[6]&0xff)<<8)|(packetData[7]&0xff));
        System.arraycopy(packetData, 8, packet.senderHit, 0, 16);
        System.arraycopy(packetData, 24, packet.receiverHit, 0, 16);

        int currentIdx = 40;
        while (currentIdx < packetData.length) {
            if (packetData.length-currentIdx < 4) {
                // Not enough data for parameter header
                return null;
            }
            int paramType = ((packetData[currentIdx]&0xff)<<8)|(packetData[currentIdx+1]&0xff);
            int paramLength = ((packetData[currentIdx+2]&0xff)<<8)|(packetData[currentIdx+3]&0xff);
            int totalLength = 11+paramLength-(paramLength+3)%8;

            if (packetData.length-currentIdx < totalLength) {
                // Not enough data for parameter contents
                System.out.println("Not enough data for contents");
                return null;
            }
            byte[] content = new byte[paramLength];
            System.arraycopy(packetData, currentIdx+4, content, 0, paramLength);
            HipParameter param = HipParameter.parse((short)paramType, content);
            if (param == null) {
                // Parsing parameter failed
                System.out.println("Parsing parameter failed");
                return null;
            }
            packet.addParameter(param);
            currentIdx += totalLength;
        }
        return packet;
    }

    public String toString() {
        String ret = "{";
        ret += " nextHeader: " + (nextHeader&0xff);
        ret += " packetType: " + (packetType&0xff);
        ret += " hipVersion: " + (hipVersion&0xff);
        ret += " controls: " + (controls&0xffff);
        ret += " senderHIT: " + HipDexUtils.byteArrayToString(senderHit);
        ret += " receiverHIT: " + HipDexUtils.byteArrayToString(receiverHit);
        if (hipParameters.size() > 0) {
            ret += " parameters: [";
            for (int i=0; i<hipParameters.size(); i++) {
                ret += " " + i + ":" + hipParameters.elementAt(i);
            }
            ret += " }";
        }
        ret += " ]";
        return ret;
    }
}
