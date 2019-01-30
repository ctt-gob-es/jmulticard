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
import java.util.logging.Logger;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.card.SmartCard;

/** Estructura de datos para almacenar la informaci&oacute;n de la MRZ,
 * tal y como se encuentra en el DG1. Basado en el documento 9303 de ICAO, partes 1 y 3.
 * @author The JMRTD team (info@jmrtd.org)
 * @version $Revision: 1712. */
public final class MrzInfo {

    /** Tipo de documento no especificado (no usar, especificar ID1 o ID3). */
    private static final int DOC_TYPE_UNSPECIFIED = 0;

    /** Tipo de documento ID1 (tama&ntilde;o CR80, MRZ de 3 l&iacute;neas de 30 caracteres). */
    private static final int DOC_TYPE_ID1 = 1;

    /** Tipo de documento ID3 (libretas de pasaporte, MRZ de dos l&iacute;neas de 44 caracteres). */
    private static final int DOC_TYPE_ID3 = 3;

    /** @deprecated
     * A reemplazar por <code>documentCode</code>. */
    @Deprecated
    private int documentType;

    private String documentCode;
    private String documentNumber;
    private String dateOfBirth;

    private String dateOfExpiry;
    private char documentNumberCheckDigit;

    /** Contiene el n&uacute;mero del titular en ciertos pa&iacute;ses (como Holanda), pero normalmente contiene parte del n&uacute;mero de documento. */
    private String optionalData1;

    /** Devuelve el 'MRZ Information' como array de octetos.
     * @return 'MRZ Information' (binario). */
    public byte[] getBytes() {
		final byte[] numberBytes = getDocumentNumber().getBytes();
		final byte[] numberCheck = new byte [] { (byte) checkDigit(getDocumentNumber()) };
		final byte[] birthBytes  = getDateOfBirth().getBytes();
		final byte[] birthCheck = new byte [] { (byte) MrzInfo.checkDigit(getDateOfBirth()) };
		final byte[] expiryBytes = getDateOfExpiry().getBytes();
		final byte[] expiryCheck = new byte[] { (byte) MrzInfo.checkDigit(getDateOfExpiry()) };

		if (SmartCard.DEBUG) {
			Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
				"Info de la MRZ: numero=" + new String(numberBytes) + //$NON-NLS-1$
					"; nacimiento=" + new String(birthBytes) + //$NON-NLS-1$
						"; caducidad=" + new String(expiryBytes) //$NON-NLS-1$
			);
		}

		return HexUtils.concatenateByteArrays(
			numberBytes,
			numberCheck,
			birthBytes,
			birthCheck,
			expiryBytes,
			expiryCheck
		);
    }

	/** Calcula el valor de inicializaci&oacute;n (BAC, EAC, PACE) de la MRZ.
	 * Siguiendo la especificaci&oacute;n ICAO 9303:<br>
	 * <code>KDF&pi;(&pi;) = KDF(f(&pi;),3)</code><br>
	 * <code>K= f(&pi;) = SHA-1(Serial Number || Date of Birth || Date of Expiry)</code><br>
	 * En este m&eacute;todo se genera el valor de K que deber&aacute; posteriormente ser
	 * pasado como par&aacute;metro de la funci&oacute;n KDF(K,3) para generar la contrase&ntilde;a.
	 * @return K Valor de inicializaci&oacute;n.
	 * @throws IOException Si no se puede obtener el valor. */
	public byte[] getMrzPswd() throws IOException {
		return new JseCryptoHelper().digest(CryptoHelper.DigestAlgorithm.SHA1, getBytes());
	}

    /** Crea la MRZ.
     * Si este texto contiene retornos de carro o tabuladores, estos se ignoran.
     * @param mrzStr texto de la MRZ. */
    public MrzInfo(final String mrzStr) {
        if (mrzStr == null || mrzStr.isEmpty()) {
            throw new IllegalArgumentException("El texto del MRZ no puede ser nulo ni vacio"); //$NON-NLS-1$
        }
        final String strMrz = mrzStr.trim().replace("\n", "").replace("\r", "").replaceAll("\t", ""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$
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

        // Linea 1, posiciones del 1 al 2: Codigo de documento
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

            // Linea 1, posiciones del 6 al 14: Numero de documento
            this.documentNumber = readString(dataIn, 9);

            // Linea 1, posicion 15: Digito de control */
            this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();

            // Linea 1, posiciones del 16 al 30: Elementos de datos opcionales
            this.optionalData1 = readStringWithFillers(dataIn, 15);

            if (this.documentNumberCheckDigit == '<') {
            	// Se interpreta el n&uacute;mero del titular como el n&uacute;mero del documento, ver nota j.
                this.documentNumber += this.optionalData1.substring(0, this.optionalData1.length() - 1);
                this.documentNumberCheckDigit = this.optionalData1.charAt(this.optionalData1.length() - 1);
                this.optionalData1 = null;
            }
            this.documentNumber = trimFillerChars(this.documentNumber);

            // Linea 2, posiciones del 1 al 6: Fecha de nacimiento
            this.dateOfBirth = readDateOfBirth(dataIn);

			// Digito de control de la fecha de nacimiento
			dataIn.readUnsignedByte();

            // Linea 2, posicion 8: Sexo
            readGender(dataIn);

            // Linea 2, posiciones del 9 al 14: fecha de caducidad
            this.dateOfExpiry = readDateOfExpiry(dataIn);

        }
        else {
        	// Asumimos aqui que es un documento de tipo ID3 (MRZ de dos lineas).

        	readCountry(dataIn);

            // Linea 1, posiciones del 6 al 44
            readNameIdentifiers(readString(dataIn, 39));

            // Linea 2
            this.documentNumber = trimFillerChars(readString(dataIn, 9));
            this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();
            readCountry(dataIn);
            this.dateOfBirth = readDateOfBirth(dataIn);
			dataIn.readUnsignedByte();
            readGender(dataIn);
            this.dateOfExpiry = readDateOfExpiry(dataIn);
        }
    }

    /** Obtiene la fecha de nacimiento del titular.
     * @return Fecha de nacimiento del titular. */
    public String getDateOfBirth() {
        return this.dateOfBirth;
    }

    /** Obtiene la fecha de caducidad del documento.
     * @return Fecha de caducidad del documento. */
    public String getDateOfExpiry() {
        return this.dateOfExpiry;
    }

    /** Obtiene el n&uacute;mero del documento.
     * @return N&uacute;mero del documento. */
    public String getDocumentNumber() {
        return this.documentNumber;
    }

    /** Calcula el d&iacute;gito de control 7-3-1 de un fragmento la MRZ.
     * @param str Fragmento de la MRZ.
     * @return D&iacute;gito de control (de '0' a '9'). */
    static char checkDigit(final String str) {
        return checkDigit(str, false);
    }

    // Metodos privados

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

    /** Lee el c&oacute;digo de estado emisor (tres letras) del flujo de entrada.
     * @param inputStream Flujo de entrada (como texto).
     * @return Estado u organizaci&oacute;n emisora del documento (c&oacute;digo de tres letras).
     * @throws IOException En cualquier error. */
    private static String readCountry(final DataInputStream inputStream) throws IOException {
        return readString(inputStream, 3);
    }

    /** Lee el sexo del titular (una letra) del flujo de entrada.
     * @param inputStream Flujo de entrada (como texto).
     * @return Sexto del titular del documento.
     * @throws IOException En cualquier error. */
    private static String readGender(final DataInputStream inputStream) throws IOException {
        final String genderStr = readString(inputStream, 1);
        return genderStr;
    }

    /** Lee la fecha de nacimiento del titular (seis d&iacute;gitos) del flujo de entrada.
     * No se comprueba que realmente sean valores num&eacute;ricos.
     * @param in Flujo de entrada (como texto).
     * @return Fecha de nacimiento del titular.
     * @throws IOException En cualquier error. */
    private static String readDateOfBirth(final DataInputStream in) throws IOException {
        return readString(in, 6);
    }

    /** Lee la fecha de caducidad del documento (seis d&iacute;gitos) del flujo de entrada.
     * No se comprueba que realmente sean valores num&eacute;ricos.
     * @param in Flujo de entrada (como texto).
     * @return Fecha de caducidad del documento.
     * @throws IOException En cualquier error. */
    private static String readDateOfExpiry(final DataInputStream in) throws IOException {
        return readString(in, 6);
    }

    /** Determina el tipo de documento seg&uacute;n el c&oacute;digo de documento (pimeros
     * dos caracteres de la MRZ).
     * <ul>
     *  <li>
     *   El documento ICAO 9303 parte 3 volumen 1 define MRTD con MRZ de tres l&iacute;neas si
     *   el c&oacute;digo de documento empieza por "A", "C", o "I"
     *   (nota j, secti&oacute;n 6.6, p&aacute;gina V-9).
     *  </li>
     *  <li>
     *   El documento ICAO 9303 parte 2 define MRV con MRZ de dos l&iacute;neas si
     *   el c&oacute;digo de documento empieza por "V".
     *  </li>
     *  <li>
     *   El documento ICAO 9303 parte 1 volumen 1 define MRP con MRZ de dos l&iacute;neas si
     *   el c&oacute;digo de documento empieza por "P"
     *   (secci&oacute;n 9.6, p&aacute;gina IV-15).
     *  </li>
     * </ul>
     * @param documentCode C&oacute;digo de documento (de dos letras).
     * @return Tipo de documento, que puese ser {@link #DOC_TYPE_ID1},
     * 		   {@link #DOC_TYPE_ID3} o {@link #DOC_TYPE_UNSPECIFIED}. */
    private static int getDocumentTypeFromDocumentCode(final String documentCode) {
        if (documentCode == null || documentCode.length() < 1 || documentCode.length() > 2) {
            throw new IllegalArgumentException(
        		"El tipo de documento debe tener uno o dos caracteres, pero se recibio: " + documentCode //$NON-NLS-1$
    		);
        }
        if (documentCode.startsWith("A") || //$NON-NLS-1$
            documentCode.startsWith("C") || //$NON-NLS-1$
            documentCode.startsWith("I")) { //$NON-NLS-1$
            	/* MRTD segun ICAO Doc 9303 parte 3 vol 1 */
            	return DOC_TYPE_ID1;
        }
        else if (documentCode.startsWith("V")) { //$NON-NLS-1$
        		/* MRV segun ICAO Doc 9303 parte 2 */
        		return DOC_TYPE_ID1;
        }
        else if (documentCode.startsWith("P")) { //$NON-NLS-1$
        		/* MRP segun ICAO Doc 9303 parte 1 vol 1 */
            	return DOC_TYPE_ID3;
        }
        return DOC_TYPE_UNSPECIFIED;
    }

    /** reemplaza el caracter '&lt;' por ' ' y elimina los espacios en blanco al principio y al final.
     * @param str Texto de entrada.
     * @return Texto con las sustituciones hechas. */
    private static String trimFillerChars(final String str) {
        final byte[] chars = str.trim().getBytes();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == '<') {
                chars[i] = ' ';
            }
        }
        return new String(chars).trim();
    }

    /** Calcula el d&iacute;gito de control 7-3-1 para un fragmento de la MRZ.
     * Si <code>preferFillerOverZero</code> est&aacute; establecido a <code>true</code> entonces
     * '&lt;' se devolver&aacute; en la comprobaci&oacute;n del d&iacute;gito 0.
     * @param str Porci&oacute;n de la MRZ.
     * @param preferFillerOverZero Preferencia de relleno.
     * @return D&iacute;gito de control (del '0' al '9' o '&lt;'). */
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
            	// No deberia pasar
                throw new IllegalStateException("Error calculando el digito de control"); //$NON-NLS-1$
            }
            char checkDigit = (char)checkDigitString.getBytes(StandardCharsets.UTF_8)[0];
            if (preferFillerOverZero && checkDigit == '0') {
                checkDigit = '<';
            }
            return checkDigit;
        }
        catch (final NumberFormatException nfe) {
            // No deberia pasar
            throw new IllegalStateException("Error calculando el digito de control: " + nfe, nfe); //$NON-NLS-1$
        }
        catch (final Exception e) {
            throw new IllegalArgumentException("Error calculando el digito de control: " + e, e); //$NON-NLS-1$
        }
    }

    /** Obtiene el valor num&eacute;rico de un carcater MRZ (para el c&aacute;lculo de
     * los d&iacute;gitos de control)
     * @param ch caracter de la MRZ.
     * @return Valor num&eacute;rico del caracter.
     * @throws NumberFormatException Si el caracter no es v&aacute;lido para una MRZ. */
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
                throw new NumberFormatException(
            		"No se ha podido decodificar el caracter del MRZ '" + ch + "' ('" + Character.toString((char) ch) + "')" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        		);
        }
    }
}
