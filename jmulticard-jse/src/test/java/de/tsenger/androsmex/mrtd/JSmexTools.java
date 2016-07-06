/*
 * JSmexTools.java
 *
 * Created on 6. Oktober 2006, 09:30
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
import java.util.StringTokenizer;

/**
 *
 * @author Tobias Senger
 */

public class JSmexTools {
    
    
    /**Converts a given String into a 8 byte array. Unused space will be filled whith <code>0xFF</code>
     *
     * @param str This String contains the PIN.
     * @return A 8 byte array with the convertes String.
     */
    public static byte[] stringToPin(String str){
        
        byte[] pin = new byte[8];
        
        for (int i=0; i<str.length(); i++) {
            pin[i] = (byte)str.charAt(i);
        }
        
        for (int i=7-(str.length()-1);i<8; i++) {
            pin[i] = (byte)0xFF;
        }
        
        return pin;
        
    }
    
    /**Converts a String which contains hexadecimal data to a byte array
     *
     * @param hexString String which contains hexadecimal data
     * @return
     */
    public static byte[] parseHexString(String hexString) throws java.lang.NumberFormatException {
        
        StringTokenizer st = new StringTokenizer(hexString);
        byte[] result = new byte[st.countTokens() ];
        
        for(int i=0; st.hasMoreTokens(); i++) {
            char[] ca=(st.nextToken()).toCharArray();
            if(ca.length!=2) throw new java.lang.NumberFormatException();
            result[i]=(byte)(parseHexChar(ca[0])*16+parseHexChar(ca[1]));
        }
        return result;
        
    }
    
    /**
     * Parse a radix 16 symbol
     * @param c a symbol
     * @note : java.lang.Integer.parseInt(String s, int radix) do not verify if symbol is correct !!
     */
    public static byte parseHexChar(char c) throws java.lang.NumberFormatException {
        
        if((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'))
            return (byte)(Character.digit(c,16));
        
        throw new java.lang.NumberFormatException();
        
    }
    
    /**Converts a byte into a unsigned integer value.
     *
     * @param value
     * @return
     */
    public static int toUnsignedInt(byte value) {
        return (value & 0x7F) + (value < 0 ? 128 : 0);
    }
    
    /**
     * Converts a a unsigned byte into a Unicode Character
     *
     * @param value
     * @return
     */
    public static char toChar(byte value) {
        return (char)toUnsignedInt(value);
    }
    
    /** Merge two byte array to a new big one.
     *
     * @param a1 Source array 1
     * @param a2 Source array 2
     * @return New byte array which contains data from the two source arrays.
     */
    public static byte[] mergeByteArray(byte[] a1, byte[] a2) {
        byte[] newArray = new byte[ a1.length + a2.length ];
        System.arraycopy( a1, 0, newArray, 0, a1.length );
        System.arraycopy( a2, 0, newArray, a1.length, a2.length );
        return newArray;
    }
    
    /**This method converts a byte array which contains BCD coded data into a String.
     * With start and end the start and end position for the conversation are specified.
     *
     * @param ba This parameter contans the byte array with the BCD coded data
     * @param start This parameter specifies the start index.
     * @param end This parameter specifies the end index.
     * @return This paramter returns the converted data.
     */
    public static String BCDByteArrayToString(byte[] ba, int start, int end) {
        StringBuffer sb = new StringBuffer();
        for (int i = start; i<end; i++) {
            sb.append(toUnsignedInt(ba[i])>>>4);
            sb.append(toUnsignedInt(ba[i])&0x0F);
        }
        return sb.toString();
    }
    
    /**Returns a copy from the given byte array.  Parameter fromstart and length are used if only a part should be copied.
     *
     * @param from Source array.
     * @param to Destination array.
     * @param fromstart Start copy position.
     * @param length Length to copy.
     */
    public static void copyByteArray(byte[] from, byte[] to, int fromstart, int length) {
        for (int i= 0;i<length;i++) to[i] = from[i+fromstart];
    }
    
}
