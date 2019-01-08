package es.gob.jmulticard.card.pace;

/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2017  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: MRZInfo.java 1712 2017-09-14 06:09:59Z martijno $
 */

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Data structure for storing the MRZ information
 * as found in DG1. Based on ICAO Doc 9303 part 1 and 3.
 * @author The JMRTD team (info@jmrtd.org)
 * @version $Revision: 1712. */
final class MrzInfo {

    /** Unspecified document type (do not use, choose ID1 or ID3). */
    private static final int DOC_TYPE_UNSPECIFIED = 0;

    /** ID1 document type for credit card sized identity cards. Specifies a 3-line MRZ, 30 characters wide. */
    private static final int DOC_TYPE_ID1 = 1;

    /** ID3 document type for passport booklets. Specifies a 2-line MRZ, 44 characters wide. */
    private static final int DOC_TYPE_ID3 = 3;

    /** @deprecated to be replaced with documentCode */
    @Deprecated
    private int documentType;

    private String documentCode;
    private String documentNumber;
    private String dateOfBirth;

    private String dateOfExpiry;
    private char documentNumberCheckDigit;
    private String optionalData1; /* NOTE: holds personal number for some issuing states (e.g. NL), but is used to hold (part of) document number for others. */

    /** Creates a new MRZ based on the text input.
     * The text input may contain newlines, which will be ignored.
     * @param str Input text. */
    void setMrz(final String str) {
        if (str == null) {
            throw new IllegalArgumentException("Null string"); //$NON-NLS-1$
        }
        final String strMrz = str.trim().replace("\n", ""); //$NON-NLS-1$ //$NON-NLS-2$
        try {
            readObject(
        		new ByteArrayInputStream(strMrz.getBytes(StandardCharsets.UTF_8)),
        		strMrz.length()
    		);
        }
        catch (final IOException ioe) {
            throw new IllegalArgumentException(ioe);
        }
    }

    private void readObject(final InputStream inputStream, final int length) throws IOException {

        final DataInputStream dataIn = new DataInputStream(inputStream);

        /* line 1, pos 1 to 2, Document code */
        this.documentCode = readStringWithFillers(dataIn, 2);
        this.documentType = getDocumentTypeFromDocumentCode(this.documentCode);
        switch (length) {
            case 88:
                this.documentType = DOC_TYPE_ID3;
                break;
            case 90:
                this.documentType = DOC_TYPE_ID1;
                break;
            default:
                this.documentType = getDocumentTypeFromDocumentCode(this.documentCode);
                break;
        }
        if (this.documentType == DOC_TYPE_ID1) {
        	readCountry(dataIn);

            /* line 1, pos 6 to 14 Document number */
            this.documentNumber = readString(dataIn, 9);

            /* line 1, pos 15 Check digit */
            this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();

            /* line 1, pos 16 to 30, Optional data elements */
            this.optionalData1 = readStringWithFillers(dataIn, 15);

            if (this.documentNumberCheckDigit == '<') {
            	/* Interpret personal number as part of document number, see note j. */
                this.documentNumber += this.optionalData1.substring(0, this.optionalData1.length() - 1);
                this.documentNumberCheckDigit = this.optionalData1.charAt(this.optionalData1.length() - 1);
                this.optionalData1 = null;
            }
            this.documentNumber = trimFillerChars(this.documentNumber);

            // line 2, pos 1 to 6, Date of birth
            this.dateOfBirth = readDateOfBirth(dataIn);

			// Date of birth check digit
			dataIn.readUnsignedByte();

            // line 2, pos 8, Sex
            readGender(dataIn);

            // line 2, Pos 9 to 14, Date of expiry
            this.dateOfExpiry = readDateOfExpiry(dataIn);

        }
        else {
        	// Assume it's a ID3 document, i.e. 2-line MRZ.

        	readCountry(dataIn);

            // line 1, pos 6 to 44
            readNameIdentifiers(readString(dataIn, 39));

            // line 2
            this.documentNumber = trimFillerChars(readString(dataIn, 9));
            this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();
            readCountry(dataIn);
            this.dateOfBirth = readDateOfBirth(dataIn);
			dataIn.readUnsignedByte();
            readGender(dataIn);
            this.dateOfExpiry = readDateOfExpiry(dataIn);
        }
    }

    /** Gets the date of birth of the passport holder.
     * @return Date of birth. */
    String getDateOfBirth() {
        return this.dateOfBirth;
    }

    /** Gets the date of expiry.
     * @return Date of expiry. */
    String getDateOfExpiry() {
        return this.dateOfExpiry;
    }

    /** Gets the document number.
     * @return Document number. */
    String getDocumentNumber() {
        return this.documentNumber;
    }

    /** Computes the 7-3-1 check digit for part of the MRZ.
     * @param str A part of the MRZ.
     * @return The resulting check digit (in '0' - '9'). */
    public static char checkDigit(final String str) {
        return checkDigit(str, false);
    }

    /* ONLY PRIVATE METHODS BELOW */

    private static void readNameIdentifiers(final String mrzNameString) {
        final int delimIndex = mrzNameString.indexOf("<<"); //$NON-NLS-1$
        if (delimIndex < 0) {
            trimFillerChars(mrzNameString);
            return;
        }
        trimFillerChars(mrzNameString.substring(0, delimIndex));
    }

    private static String readString(final DataInputStream in, final int count) throws IOException {
        final byte[] data = new byte[count];
        in.readFully(data);
        return new String(data).trim();
    }

    private static String readStringWithFillers(final DataInputStream in, final int count) throws IOException {
        return trimFillerChars(readString(in, count));
    }

    /** Reads the issuing state as a three letter string.
     * @param inputStream The inpt string stream.
     * @return A string of length 3 containing an abbreviation
     *         of the issuing state or organization.
     * @throws IOException If something goes wrong. */
    private static String readCountry(final DataInputStream inputStream) throws IOException {
        return readString(inputStream, 3);
    }

    /** Reads The 1 letter gender information.
     * @param inputStream The input source.
     * @return The gender of the passport holder.
     * @throws IOException If something goes wrong. */
    private static String readGender(final DataInputStream inputStream) throws IOException {
        final String genderStr = readString(inputStream, 1);
        return genderStr;
    }

    /** Reads the date of birth of the passport holder.
     * As only the rightmost two digits are stored,
     * the assumption that this is a date in the recent
     * past is made.
     * @param in The input string stream.
     * @return The date of birth.
     * @throws IOException If something goes wrong.
     * @throws NumberFormatException If a data could not be constructed. */
    private static String readDateOfBirth(final DataInputStream in) throws IOException, NumberFormatException {
        return readString(in, 6);
    }

    /** Reads the date of expiry of this document.
     * As only the rightmost two digits are stored,
     * the assumption that this is a date in the near
     * future is made.
     * @param in The input string stream.
     * @return The date of expiry.
     * @throws IOException If something goes wrong.
     * @throws NumberFormatException If a date could not be constructed. */
    private static String readDateOfExpiry(final DataInputStream in) throws IOException, NumberFormatException {
        return readString(in, 6);
    }

    /** Determines the document type based on the document code (the first two characters of the MRZ).
     * ICAO Doc 9303 part 3 vol 1 defines MRTDs with 3-line MRZs,
     * in this case the document code starts with "A", "C", or "I"
     * according to note j to Section 6.6 (page V-9).
     *
     * ICAO Doc 9303 part 2 defines MRVs with 2-line MRZs,
     * in this case the document code starts with "V".
     *
     * ICAO Doc 9303 part 1 vol 1 defines MRPs with 2-line MRZs,
     * in this case the document code starts with "P"
     * according to Section 9.6 (page IV-15).
     *
     * @param documentCode A two letter code.
     * @return A document type, one of {@link #DOC_TYPE_ID1},
     * 		   {@link #DOC_TYPE_ID3}, or {@link #DOC_TYPE_UNSPECIFIED} */
    private static int getDocumentTypeFromDocumentCode(final String documentCode) {
        if (documentCode == null || documentCode.length() < 1 || documentCode.length() > 2) {
            throw new IllegalArgumentException("Was expecting 1 or 2 digit document code, got " + documentCode); //$NON-NLS-1$
        }
        if (documentCode.startsWith("A") || //$NON-NLS-1$
            documentCode.startsWith("C") || //$NON-NLS-1$
            documentCode.startsWith("I")) { //$NON-NLS-1$
            	/* MRTD according to ICAO Doc 9303 part 3 vol 1 */
            	return DOC_TYPE_ID1;
        }
        else if (documentCode.startsWith("V")) { //$NON-NLS-1$
        		/* MRV according to ICAO Doc 9303 part 2 */
        		return DOC_TYPE_ID1;
        }
        else if (documentCode.startsWith("P")) { //$NON-NLS-1$
        		/* MRP according to ICAO Doc 9303 part 1 vol 1 */
            	return DOC_TYPE_ID3;
        }
        return DOC_TYPE_UNSPECIFIED;
    }

    /** Replaces '&lt;' with ' ' and trims leading and trailing whitespace.
     * @param str The input string.
     * @return Trimmed string. */
    private static String trimFillerChars(final String str) {
        final byte[] chars = str.trim().getBytes();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == '<') {
                chars[i] = ' ';
            }
        }
        return new String(chars).trim();
    }

    /** Computes the 7-3-1 check digit for part of the MRZ.
     * If <code>preferFillerOverZero</code> is <code>true</code> then '&lt;' will be
     * returned on check digit 0.
     * @param str A part of the MRZ.
     * @param preferFillerOverZero Fill preference.
     * @return The resulting check digit (in '0' - '9', '&lt;'). */
    private static char checkDigit(final String str, final boolean preferFillerOverZero) {
        try {
            final byte[] chars = str == null ? new byte[] { } : str.getBytes(StandardCharsets.UTF_8);
            final int[] weights = { 7, 3, 1 };
            int result = 0;
            for (int i = 0; i < chars.length; i++) {
                result = (result + weights[i % 3] * decodeMRZDigit(chars[i])) % 10;
            }
            final String checkDigitString = Integer.toString(result);
            if (checkDigitString.length() != 1) {
                throw new IllegalStateException("Error in computing check digit."); /* NOTE: Never happens. */ //$NON-NLS-1$
            }
            char checkDigit = (char)checkDigitString.getBytes(StandardCharsets.UTF_8)[0];
            if (preferFillerOverZero && checkDigit == '0') {
                checkDigit = '<';
            }
            return checkDigit;
        }
        catch (final NumberFormatException nfe) {
            /* NOTE: never happens. */
            throw new IllegalStateException("Error in computing check digit", nfe); //$NON-NLS-1$
        }
        catch (final Exception e) {
            throw new IllegalArgumentException("Error in computing check digit", e); //$NON-NLS-1$
        }
    }

    /** Looks up the numerical value for MRZ characters. In order to be able
     * to compute check digits.
     * @param ch A character from the MRZ.
     * @return The numerical value of the character.
     * @throws NumberFormatException If <code>ch</code> is not a valid MRZ
     *                               character. */
    private static int decodeMRZDigit(final byte ch) throws NumberFormatException {
        switch (ch) {
            case '<':
            case '0':
                return 0;
            case '1':
                return 1;
            case '2':
                return 2;
            case '3':
                return 3;
            case '4':
                return 4;
            case '5':
                return 5;
            case '6':
                return 6;
            case '7':
                return 7;
            case '8':
                return 8;
            case '9':
                return 9;
            case 'a':
            case 'A':
                return 10;
            case 'b':
            case 'B':
                return 11;
            case 'c':
            case 'C':
                return 12;
            case 'd':
            case 'D':
                return 13;
            case 'e':
            case 'E':
                return 14;
            case 'f':
            case 'F':
                return 15;
            case 'g':
            case 'G':
                return 16;
            case 'h':
            case 'H':
                return 17;
            case 'i':
            case 'I':
                return 18;
            case 'j':
            case 'J':
                return 19;
            case 'k':
            case 'K':
                return 20;
            case 'l':
            case 'L':
                return 21;
            case 'm':
            case 'M':
                return 22;
            case 'n':
            case 'N':
                return 23;
            case 'o':
            case 'O':
                return 24;
            case 'p':
            case 'P':
                return 25;
            case 'q':
            case 'Q':
                return 26;
            case 'r':
            case 'R':
                return 27;
            case 's':
            case 'S':
                return 28;
            case 't':
            case 'T':
                return 29;
            case 'u':
            case 'U':
                return 30;
            case 'v':
            case 'V':
                return 31;
            case 'w':
            case 'W':
                return 32;
            case 'x':
            case 'X':
                return 33;
            case 'y':
            case 'Y':
                return 34;
            case 'z':
            case 'Z':
                return 35;
            default:
                throw new NumberFormatException("Could not decode MRZ character " + ch + " ('" + Character.toString((char) ch) + "')"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        }
    }
}
