//
// HipHitSuiteList - HIT_SUITE_LIST parameter
//
// Authors:
//      Juho V�h�-Herttua  <juhovh@iki.fi>
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

public class HipHitSuiteList extends HipParameter {
    public static final byte ECDH_DEX = 8;

    public short getType() {
        return HipParameter.HIT_SUITE_LIST;
    }

    public int getContentLength() {
        return 1;
    }

    public byte[] getContents() {
        return new byte[] { ECDH_DEX };
    }

    protected boolean parseContent(byte[] content) {
        return true;
    }
}
