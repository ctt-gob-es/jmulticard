/*
 * ASN1Tools.java
 *
 * Created on 15. November 2007
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
public class ASN1Tools {
    
    /** Creates a new instance of ASN1Tools */
    public ASN1Tools() {
        
    }
    
    private static int asn1DataLength(byte[] asn1Data, int startByte) {
        if (JSmexTools.toUnsignedInt(asn1Data[(startByte+1)]) <= 0x7f) 
            return JSmexTools.toUnsignedInt(asn1Data[(startByte+1)]);
        
        if (JSmexTools.toUnsignedInt(asn1Data[(startByte+1)]) == 0x81) 
            return JSmexTools.toUnsignedInt(asn1Data[(startByte+2)]);
        
        if (JSmexTools.toUnsignedInt(asn1Data[(startByte+1)]) == 0x82) 
            return (JSmexTools.toUnsignedInt(asn1Data[(startByte+2)])*256+JSmexTools.toUnsignedInt(asn1Data[(startByte+3)]));
        
	return 0;
    }
    
    public static byte[] extractTag(byte tag, byte[] data, int startByte) {
        for (int i = startByte;i<data.length;i++) {
            if (data[i]==tag) {
                int len = asn1DataLength(data.clone(), i);
                
                int addlen = 2;
                if (data[i+1] == (byte)0x81) addlen = 3;
                else if (data[i+1] == (byte)0x82) addlen = 4;
                
                byte[] dataObject = new byte[(len+addlen)];
                
                System.arraycopy(data,i,dataObject,0,dataObject.length);
                
                return dataObject;
            }
        }
        return null;
    }
    
    public static byte[] extractTLV(short tag, byte[] data, int startByte) {
        for (int i = startByte;i<data.length;i++) {
            if (JSmexTools.toUnsignedInt(data[i])*0x100+JSmexTools.toUnsignedInt(data[i+1])==tag) {
                int len = asn1DataLength(data.clone(), i+1);
                
                int addlen = 3;
                if (data[i+2] == (byte)0x81) addlen = 4;
                else if (data[i+2] == (byte)0x82) addlen = 5;
                
                byte[] dataObject = new byte[(len+addlen)];
                
                System.arraycopy(data,i,dataObject,0,dataObject.length);
                
                return dataObject;
            }
        }
        return null;
    }
    
}
