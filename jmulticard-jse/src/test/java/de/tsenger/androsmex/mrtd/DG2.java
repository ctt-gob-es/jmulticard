/*
 * DG2DataContainer.java
 *
 * Created on 13. November 2007
 *
 *  This file is part of JSmex.
 *
 *  JSmex is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  JSmex is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package de.tsenger.androsmex.mrtd;

/**
 *
 * @author Tobias Senger
 */
public class DG2 {

    private static final byte FACIAL_BIOMETRIC_DATA_GROUP_TAG = (byte) 0x75;
    private static final short BIOMETRIC_INFO_GROUP_TAG = 0x7F61;
    private static final short BIOMETRIC_INFO_TAG = 0x7F60;
    private static final short BIOMETRIC_DATA_TAG = 0x5F2E;
    private static final byte BIOMETRIC_HEADER_TEMPLATE_TAG = (byte) 0xA1;
    private static final byte FORMAT_OWNER_TAG = (byte) 0x87;
    private static final byte FORMAT_TYPE_TAG = (byte) 0x88;
    private final byte[] imageBytes;
    private final byte[] rawData;

    /** Creates a new instance of DG2DataContainer */
    public DG2(final byte[] rawBytes) {

        this.rawData = rawBytes.clone();

        final byte[] bioInfoGroup = ASN1Tools.extractTLV((short)0x7F61,rawBytes,0);
        final byte[] bioInfo = ASN1Tools.extractTLV((short)0x7F60,bioInfoGroup,0);
        final byte[] bioDataBlock = ASN1Tools.extractTLV((short)0x5F2E,bioInfo,0);


        //attention! Quick'n'Dirty solution:
        final byte[] imageData = new byte[bioDataBlock.length-51];
        System.arraycopy(bioDataBlock,51,imageData,0,imageData.length);
        this.imageBytes = imageData.clone();

    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public byte[] getImageBytes() {
        return this.imageBytes;
    }
//
//    public Bitmap getImage() {
//        return image;
//    }
//
//    private Bitmap readImage(InputStream in) {
//    	edu.umb.cs.efg.jpeg2000.io.DataInputStream din = null;
//		try {
//			din = new edu.umb.cs.efg.jpeg2000.io.DataInputStream(in);
//		} catch (IOException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
//    	JP2Reader reader;
//    	JP2 j2kFile = null;
//		try {
//			reader = new JP2Reader(din);
//			j2kFile = reader.read();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (UnknownBoxException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		byte[] ibytes = j2kFile.getCodestreamBytes();
//		Bitmap image = BitmapFactory.decodeByteArray(ibytes, 0, ibytes.length);
//    	return image;
//    }

}
