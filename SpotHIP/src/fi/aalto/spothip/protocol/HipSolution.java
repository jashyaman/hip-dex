//
// HipSolution - SOLUTION parameter
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

public class HipSolution extends HipParameter {
    private byte k;
    private short opaque;
    private byte[] randomI = new byte[0];
    private byte[] solutionJ = new byte[0];

    protected HipSolution() {}

    public HipSolution(byte complexity, byte[] puzzleI, byte[] puzzleJ) {
        k = complexity;
        opaque = 0;
        randomI = new byte[puzzleI.length];
        System.arraycopy(puzzleI, 0, randomI, 0, puzzleI.length);
        solutionJ = new byte[puzzleJ.length];
        System.arraycopy(puzzleJ, 0, solutionJ, 0, puzzleJ.length);
    }

    public byte[] getRandomI() {
        return randomI;
    }

    public byte[] getSolutionJ() {
        return solutionJ;
    }

    public short getType() {
        return HipParameter.SOLUTION;
    }

    public int getContentLength() {
        return 4+randomI.length+solutionJ.length;
    }

    public byte[] getContents() {
        byte[] ret = new byte[getContentLength()];
        ret[0] = k;
        ret[2] = (byte) ((opaque>>8)&0xff);
        ret[3] = (byte) (opaque&0xff);
        System.arraycopy(randomI, 0, ret, 4, randomI.length);
        System.arraycopy(solutionJ, 0, ret, 4+randomI.length, solutionJ.length);
        return ret;
    }

    protected boolean parseContent(byte[] content) {
       if (content.length < 4)
            return false;

        k = content[0];
        opaque = (short)(((content[2]&0xff)<<8)|(content[3]&0xff));
        randomI = new byte[(content.length-4)/2];
        solutionJ = new byte[(content.length-4)/2];
        System.arraycopy(content, 4, randomI, 0, randomI.length);
        System.arraycopy(content, 4+randomI.length, solutionJ, 0, solutionJ.length);
        return true;
    }
}
