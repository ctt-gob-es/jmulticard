/*
 * EFCOMDataContainer.java
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
public class EF_COM {
    
    private byte[] tlvAppTemplate = null;
    private byte[] tlvLdsVersion = null;
    private byte[] tlvUnicodeVersion = null;
    private byte[] tlvTagList = null;
    
    private byte[] rawData;
    
    /** Creates a new instance of EFCOMDataContainer */
    public EF_COM(byte[] rawBytes) {
        
        this.rawData = rawBytes.clone();
        
        tlvAppTemplate = ASN1Tools.extractTag((byte)0x60,rawBytes,0);
        tlvLdsVersion = ASN1Tools.extractTLV((short)0x5F01,tlvAppTemplate,0);
        tlvUnicodeVersion = ASN1Tools.extractTLV((short)0x5F36,tlvAppTemplate,4);
        tlvTagList = ASN1Tools.extractTag((byte)0x5C,tlvAppTemplate,10);
        
    }
    
    public byte[] getBytes() {
        return rawData;
    }
    
    public String getLDSVersion() {
        byte a1 = tlvLdsVersion[3];
        byte a2 = tlvLdsVersion[4];
        byte b1 = tlvLdsVersion[5];
        byte b2 = tlvLdsVersion[6];
        return JSmexTools.toChar(a1)+""+JSmexTools.toChar(a2)+"."+JSmexTools.toChar(b1)+""+JSmexTools.toChar(b2);
    }
    
    public String getUnicodeVersion() {
        byte a1 = tlvUnicodeVersion[3];
        byte a2 = tlvUnicodeVersion[4];
        byte b1 = tlvUnicodeVersion[5];
        byte b2 = tlvUnicodeVersion[6];
        byte c1 = tlvUnicodeVersion[7];
        byte c2 = tlvUnicodeVersion[8];
        return JSmexTools.toChar(a1)+""+JSmexTools.toChar(a2)+"."+JSmexTools.toChar(b1)
                +""+JSmexTools.toChar(b2)+"."+JSmexTools.toChar(c1)+""+JSmexTools.toChar(c2);
    }
    
    public byte[] getTagList() {
        byte[] tagList = new byte[tlvTagList[1]];
        System.arraycopy(tlvTagList,2,tagList,0,tagList.length);
        return tagList;
    }
    
}
