//
// HipDhGroupList - DH_GROUP_LIST parameter
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

public class HipDhGroupList extends HipParameter {
    public static final byte DH_GROUP_ECP160 = 7;
    public static final byte DH_GROUP_ECP256 = 8;
    public static final byte DH_GROUP_ECP384 = 9;
    public static final byte DH_GROUP_ECP521 = 10;

    private byte[] list;

    protected HipDhGroupList() {
        list = new byte[0];
    }
    
    public HipDhGroupList(byte dhGroup) {
        list = new byte[] { dhGroup };
    }

    public HipDhGroupList(byte[] dhGroupList) {
        list = dhGroupList;
    }

    public boolean equals(Object object) {
        if (object instanceof HipDhGroupList)
            return equals((HipDhGroupList)object);
        return false;
    }

    public boolean equals(HipDhGroupList other) {
        if (list.length != other.list.length) {
            return false;
        }
        for (int i=0; i<list.length; i++) {
            if (list[i] != other.list[i]) {
                return false;
            }
        }
        return true;
    }

    public short getType() {
        return HipParameter.DH_GROUP_LIST;
    }

    public int getContentLength() {
        return list.length;
    }

    public byte[] getContents() {
        return list;
    }

    protected boolean parseContent(byte[] content) {
        list = content;
        return true;
    }
}
