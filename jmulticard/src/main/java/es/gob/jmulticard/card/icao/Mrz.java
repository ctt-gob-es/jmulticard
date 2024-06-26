
package es.gob.jmulticard.card.icao;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.DigestAlgorithm;
import es.gob.jmulticard.HexUtils;

/** MRZ de un MRTD ICAO.
 * @author The JMRTD team (info@jmrtd.org)
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Mrz {

    private final SimpleDateFormat sdFormat = new SimpleDateFormat("yyMMdd"); //$NON-NLS-1$

	private final String mrzString;
    private final byte[] rawData;

    private final String documentCode;
    private final IcaoDocumentType documentType;
    private final String issuerCountry;

    /** N&uacute;mero de soporte. */
    private final String documentNumber;

    private final String name;
    private final String surname;
    private final String dateOfBirth;
    private final String sex;
    private final String dateOfExpiry;
    private final String nationality;
    private final String subjectNumber;

    private final IcaoDocumentVariant documentVariant;

    /** Construye la MRZ del un MRTD a partir de su representaci&oacute;n
     * textual tal y como est&aacute; immpresa en el soporte.
     * @param mrzStr Texto de la MRZ impresa.
     * @throws IOException Si la MRZ no se puede analizar por no estar en el formato esperado. */
    public Mrz(final String mrzStr) throws IOException {
    	this(mrzStr == null ? null: mrzStr.trim().replace("\n", "").replace("\r", "").replace("\t", "").getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$
    }

    /** Construye la MRZ del un MRTD a partir del contenido del fichero DG1 o de su representaci&oacute;n
     * textual tal y como est&aacute; immpresa en el soporte.
     * @param rawBytes Contenido del fichero DG1 del MRTD o texto de la MRZ impresa.
     * @throws IOException Si la MRZ no se puede analizar por no estar en el formato esperado. */
    public Mrz(final byte[] rawBytes) throws IOException {

    	if (rawBytes == null || rawBytes.length < 3) {
    		throw new IllegalArgumentException("La MRZ no puede ser nula ni vacia"); //$NON-NLS-1$
    	}

        rawData = rawBytes.clone();

    	// Miramos primero si lo que nos llega el es DG1 o el texto sin empaquetar
        if (rawBytes[0] == 0x61 && rawBytes[2] == 0x5f && rawBytes[3] == 0x1f) {
        	final byte[] mrzBytes = new byte[rawData[4]];
            System.arraycopy(rawData, 5, mrzBytes, 0, mrzBytes.length);
            mrzString = new String(mrzBytes);
        }
        else {
        	mrzString = new String(rawBytes);
        }

        // Metemos los datos en un DataInputStream para ir leyendo los campos
        final DataInputStream dataIn = new DataInputStream(
    		new ByteArrayInputStream(
				mrzString.getBytes(StandardCharsets.UTF_8)
			)
		);

        // Linea 1, posiciones del 1 al 2: Codigo de documento, que nos dice si es una MRZ de dos o tres lineas
        documentCode = readStringWithFillers(dataIn, 2);
        documentType = IcaoDocumentType.getIcaoDocumentType(documentCode);

        documentVariant = IcaoDocumentVariant.getIcaoDocumentVariant(documentCode);

        // Linea 1, posiciones del 3 a la 5: Pais
        issuerCountry = readString(dataIn, 3);

    	switch (documentType) {
    		case DOC_TYPE_ID1: // MRZ de tres lineas

                // Linea 1, posiciones del 6 al 14: Numero de documento
                String tmpDocNum = readString(dataIn, 9);

                // Linea 1, posicion 15: Digito de control
                char documentNumberCheckDigit = (char) dataIn.readUnsignedByte();

                // Linea 1, posiciones del 16 al 30: Elementos de datos opcionales
                String optionalData1 = readStringWithFillers(dataIn, 15);

                if (documentNumberCheckDigit == '<') {
                	// Se interpreta el numero del titular como el numero del documento, ver nota j.
                	tmpDocNum += optionalData1.substring(0, optionalData1.length() - 1);
                	//documentNumberCheckDigit = optionalData1.charAt(optionalData1.length() - 1);
                    optionalData1 = null;
                }
                subjectNumber = optionalData1;

                documentNumber = trimFillerChars(tmpDocNum);

        		// Linea 2, posiciones del 1 al 6: Fecha de nacimiento
        		dateOfBirth = readString(dataIn, 6);

        		// Linea 2, posicion 7: Digito de control de la fecha de nacimiento
        		dataIn.readUnsignedByte();

        		// Linea 2, posicion 8: Sexo
        		sex = readString(dataIn, 1);

        		// Linea 2, posiciones del 9 al 14: fecha de caducidad
        		dateOfExpiry = readString(dataIn, 6);

        		// Linea 2, posicion 15: Digito de control de la fecha de caducidad
        		dataIn.readUnsignedByte();

        		// Linea 2, posiciones del 16 al 18: nacionalidad
        		nationality = readString(dataIn, 3);

        		// Linea 2, posiciones del 19 al 30: Digito de control del documento (se ignora)
        		readString(dataIn, 12);

        		// Linea 3, posiciones del 1 al 30: Nombre y apellidos
        		String mrzNameString = readString(dataIn, 30);
    	        int delimIndex = mrzNameString.indexOf("<<"); //$NON-NLS-1$
    	        if (delimIndex < 0) {
    	        	name = trimFillerChars(mrzNameString);
    	        	surname = null;
    	        }
    	        else {
    	        	surname = trimFillerChars(mrzNameString.substring(0, delimIndex));
    	        	name = trimFillerChars(mrzNameString.substring(delimIndex));
    	        }

    			break;

    		case DOC_TYPE_ID3: // MRZ de dos lineas

    			// Linea 1, posiciones del 6 al 44: Nombre y apellidos
    			mrzNameString = readString(dataIn, 39);
    	        delimIndex = mrzNameString.indexOf("<<"); //$NON-NLS-1$
    	        if (delimIndex < 0) {
    	        	name = trimFillerChars(mrzNameString);
    	        	surname = null;
    	        }
    	        else {
    	        	surname = trimFillerChars(mrzNameString.substring(0, delimIndex));
    	        	name = trimFillerChars(mrzNameString.substring(delimIndex));
    	        }

    	        // Linea 2, posiciones del 1 al 9: Numero del soporte
                documentNumber = trimFillerChars(readString(dataIn, 9));

                // Linea 2, posicion 10: Digito de control del soporte
                documentNumberCheckDigit = (char) dataIn.readUnsignedByte();

                // Linea 2, posiciones del 11 al 13; Nacionalidad del titular
                nationality = readString(dataIn, 3);

        		// Linea 2, posiciones del 14 al 19: Fecha de nacimiento
        		dateOfBirth = readString(dataIn, 6);

        		// Linea 2, posicion 20: Digito de control de la fecha de nacimiento
        		dataIn.readUnsignedByte();

        		// Linea 2, posicion 21: Sexo
        		sex = readString(dataIn, 1);

        		// Linea 2, posiciones del 22 al 27: fecha de caducidad
        		dateOfExpiry = readString(dataIn, 6);

        		// Linea 2, posicion 28: Digito de control de la fecha de caducidad
        		dataIn.readUnsignedByte();

        		// Linea 2, posiciones del 29 al 42
        		subjectNumber = trimFillerChars(readString(dataIn, 14));

    			break;

			default:
				throw new IllegalArgumentException("Tipo de documento no soportado: " + documentType); //$NON-NLS-1$
    	}
    }

    @Override
	public String toString() {
    	return mrzString;
    }

    /** Obtiene el contenido binario del MRZ.
     * Puede ser el contenido del fichero DG1 del MRTD o simplemente el texto impreso en el soporte.
     * @return Contenido binario del MRZ. */
	public byte[] getBytes() {
        return rawData.clone();
    }

    private static String readString(final DataInputStream stringStream, final int count) throws IOException {
        final byte[] data = new byte[count];
        stringStream.readFully(data);
        return new String(data).trim();
    }

    /** Reemplaza el caracter '&lt;' por ' ' y elimina los espacios en blanco al principio y al final.
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

    private static String readStringWithFillers(final DataInputStream stringStream, final int count) throws IOException {
        return trimFillerChars(readString(stringStream, count));
    }

    /** Obtiene el nombre del titular.
     * @return Nombre del titular. */
	public String getName() {
        return name;
    }

	/** Obtiene los apellidos del titular.
     * @return Apellidos del titular. */
	public String getSurname() {
        return surname;
    }

	/** Obtiene la fecha de nacimiento del titular.
     * @return Fecha de nacimiento del titular.
     * @throws ParseException Si la fecha encontrada no est&aacute; en el
     *         formato esperado. */
	public Date getDateOfBirth() throws ParseException {
        return sdFormat.parse(dateOfBirth);
    }

	/** Obtiene la nacionalidad del titular.
     * @return Nacionalidad del titular. */
	public String getNationality() {
        final String c = CountryCodes.getCountryName(nationality);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

	/** Obtiene el sexo del titular.
     * @return Sexo del titular. */
	public Gender getSex() {
    	return Gender.getGender(sex);
    }

	/** Obtiene la fecha de caducidad del MRTD.
     * @return Fecha de caducidad del MRTD.
     * @throws ParseException Si la fecha encontrada no est&aacute; en el formato esperado. */
	public synchronized Date getDateOfExpiry() throws ParseException {
        return sdFormat.parse(dateOfExpiry);
    }

	/** Obtiene el n&uacute;mero de soporte del MRTD.
     * @return N&uacute;mero de soporte del MRTD. */
	public String getDocumentNumber() {
        return documentNumber;
    }

	/** Obtiene el pa&iacute;s emisor del MRTD.
     * @return Pa&iacute;s emisor del MRTD. */
	public String getIssuerCountry() {
    	final String c = CountryCodes.getCountryName(issuerCountry);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

	/** Obtiene el tipo de MRTD.
     * @return Tipo de MRTD. */
	public IcaoDocumentType getDocumentType() {
        return documentType;
    }

    /** Obtiene el n&uacute;mero del MRTD.
     * @return N&uacute;mero del MRTD. */
	public String getSubjectNumber() {
		return subjectNumber;
	}

    /** Obtiene el contenido binario directo del objeto DG01.
     * @return Contenido binario directo del objeto DG01. */
    public byte[] getRawData() {
        return rawData.clone();
    }

    /** Devuelve el 'MRZ Information' como array de octetos.
     * @return 'MRZ Information' (binario). */
    public byte[] getMrzInformation() {
		final byte[] numberBytes = getDocumentNumber().getBytes();
		final byte[] numberCheck = { (byte) checkDigit(getDocumentNumber()) };
		final byte[] birthBytes  = dateOfBirth.getBytes();
		final byte[] birthCheck = { (byte) checkDigit(dateOfBirth) };
		final byte[] expiryBytes = dateOfExpiry.getBytes();
		final byte[] expiryCheck = { (byte) checkDigit(dateOfExpiry) };

		return HexUtils.concatenateByteArrays(
			numberBytes,
			numberCheck,
			birthBytes,
			birthCheck,
			expiryBytes,
			expiryCheck
		);
    }

    /** Calcula el d&iacute;gito de control 7-3-1 de un fragmento la MRZ.
     * @param str Fragmento de la MRZ.
     * @return D&iacute;gito de control (de '0' a '9'). */
    private static char checkDigit(final String str) {
        return checkDigit(str, false);
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
                result = (result + weights[i % 3] * decodeMrzDigit(chars[i])) % 10;
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
            throw new IllegalStateException("Error calculando el digito de control", nfe); //$NON-NLS-1$
        }
        catch (final Exception e) {
            throw new IllegalArgumentException("Error calculando el digito de control", e); //$NON-NLS-1$
        }
    }

    /** Obtiene el valor num&eacute;rico de un caracter MRZ (para el
     * c&aacute;lculo de los d&iacute;gitos de control).
     * @param ch Caracter de la MRZ.
     * @return Valor num&eacute;rico del caracter.
     * @throws NumberFormatException Si el caracter no es v&aacute;lido para una MRZ. */
    private static int decodeMrzDigit(final byte ch) {
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

	/** Calcula el valor de inicializaci&oacute;n (BAC, EAC, PACE) de la MRZ.
	 * Siguiendo la especificaci&oacute;n ICAO 9303:<br>
	 * <code>KDF&pi;(&pi;) = KDF(f(&pi;),3)</code><br>
	 * <code>K= f(&pi;) = SHA-1(Serial Number || Date of Birth || Date of Expiry)</code>.<br>
	 * Aqu&iacute; se genera el valor de K que deber&aacute; posteriormente ser
	 * pasado como par&aacute;metro de la funci&oacute;n KDF(K,3) para generar la contrase&ntilde;a.
	 * @param cryptoHelper Clase para la realizaci&oacute;n de operaciones criptogr&aacute;ficas.
	 * @return K Valor de inicializaci&oacute;n.
	 * @throws IOException Si no se puede obtener el valor. */
	public byte[] getMrzPswd(final CryptoHelper cryptoHelper) throws IOException {
		return cryptoHelper.digest(
			DigestAlgorithm.SHA1,
			getMrzInformation()
		);
	}

	/** Obtiene la variante de este MRTD.
	 * @return Variante de este MRTD. */
	public IcaoDocumentVariant getDocumentVariant() {
		return documentVariant;
	}

	/** Variante de documento de identidad. */
	public enum IcaoDocumentVariant {

		/** Permiso de residencia o asilo. */
		DOC_VAR_IR("Permiso de residencia o asilo"), //$NON-NLS-1$

		/** Tarjeta de identidad. */
		DOC_VAR_ID("Tarjeta de identidad"), //$NON-NLS-1$

		/** Tarjeta de residencia de familiar de ciudadano de la UE. */
		DOC_VAR_IM("Tarjeta de residencia de familiar de ciudadano de la UE"), //$NON-NLS-1$

		/** Permiso de estancia temporal. */
		DOC_VAR_IT("Permiso de estancia temporal"), //$NON-NLS-1$

		/** Tarjeta de trabajador transfronterizo. */
		DOC_VAR_IX("Tarjeta de trabajador transfronterizo"), //$NON-NLS-1$

		/** Documento de identidad del marino. */
		DOC_VAR_IS("Documento de identidad del marino"), //$NON-NLS-1$

		/** Pasaporte. */
		DOC_VAR_P("Pasaporte"), //$NON-NLS-1$

		/** Documento de identidad no especificado. */
		DOC_VAR_OTHER("Documento de identidad no especificado"); //$NON-NLS-1$

		private final String description;

		IcaoDocumentVariant(final String d) {
			description = d;
		}

		@Override
		public String toString() {
			return description;
		}

		/** Obtiene la variante del MRTD.
		 * @param documentCode C&oacute;digo de documento (las dos primeras letras de la MRZ).
		 * @return Variante del MRTD. */
		static IcaoDocumentVariant getIcaoDocumentVariant(final String documentCode) {
			if (documentCode.startsWith("IR")) { //$NON-NLS-1$
				return DOC_VAR_IR;
			}
			if (documentCode.startsWith("ID")) { //$NON-NLS-1$
				return DOC_VAR_ID;
			}
			if (documentCode.startsWith("IM")) { //$NON-NLS-1$
				return DOC_VAR_IM;
			}
			if (documentCode.startsWith("IT")) { //$NON-NLS-1$
				return DOC_VAR_IT;
			}
			if (documentCode.startsWith("IX")) { //$NON-NLS-1$
				return DOC_VAR_IX;
			}
			if (documentCode.startsWith("IS")) { //$NON-NLS-1$
				return DOC_VAR_IS;
			}
			if (documentCode.startsWith("P")) { //$NON-NLS-1$
				return DOC_VAR_P;
			}
			return DOC_VAR_OTHER;
		}
	}

    /** Tipo de documento ICAO. */
    public enum IcaoDocumentType {

    	/** MRV segun ICAO Doc 9303 parte 2). */
    	DOC_TYPE_ID1,

    	/** MRP segun ICAO Doc 9303 parte 1 vol 1. */
    	DOC_TYPE_ID3,

    	/** Tipo desconocido. */
    	DOC_TYPE_UNSPECIFIED;

        /** Determina el tipo de documento seg&uacute;n el c&oacute;digo de documento (primeros
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
         * @return Tipo de documento. */
    	static IcaoDocumentType getIcaoDocumentType(final String documentCode) {
            if (documentCode == null || documentCode.length() < 1 || documentCode.length() > 2) {
                throw new IllegalArgumentException(
            		"El tipo de documento debe tener uno o dos caracteres, pero se recibio: " + documentCode //$NON-NLS-1$
        		);
            }
            if (documentCode.startsWith("A") || //$NON-NLS-1$
                documentCode.startsWith("C") || //$NON-NLS-1$
                documentCode.startsWith("I") || //$NON-NLS-1$
                documentCode.startsWith("V")    //$NON-NLS-1$
            ) {
        		// MRV segun ICAO Doc 9303 parte 2
        		return DOC_TYPE_ID1;
            }
    		if (documentCode.startsWith("P")) { //$NON-NLS-1$
        		// MRP segun ICAO Doc 9303 parte 1 vol 1
            	return DOC_TYPE_ID3;
            }
            return DOC_TYPE_UNSPECIFIED;
    	}
    }
}
