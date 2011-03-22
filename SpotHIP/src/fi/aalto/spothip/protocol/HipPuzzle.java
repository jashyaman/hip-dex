//
// HipPuzzle - PUZZLE parameter
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

public class HipPuzzle extends HipParameter {
    private byte k;
    private byte lifetime;
    private short opaque;
    private byte[] randomI;

    public HipPuzzle(int complexity, byte[] puzzleI) {
        k = (byte)complexity;
        lifetime = 64;
        opaque = 0;
        randomI = new byte[puzzleI.length];
        System.arraycopy(puzzleI, 0, randomI, 0, puzzleI.length);
    }

    public short getType() {
        return HipParameter.PUZZLE;
    }

    public int getContentLength() {
        return 4+randomI.length;
    }

    public byte getComplexity() {
        return k;
    }

    public byte[] getRandomI() {
        return randomI;
    }

    public byte[] getContents() {
        byte[] ret = new byte[getContentLength()];
        ret[0] = k;
        ret[1] = lifetime;
        ret[2] = (byte) ((opaque>>8)&0xff);
        ret[3] = (byte) (opaque&0xff);
        System.arraycopy(randomI, 0, ret, 4, randomI.length);
        return ret;
    }
}
