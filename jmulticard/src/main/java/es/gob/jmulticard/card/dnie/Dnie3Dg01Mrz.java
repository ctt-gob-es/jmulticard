
package es.gob.jmulticard.card.dnie;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

/** Zona ICAO MRZ del DNIe 3.0.*/
public final class Dnie3Dg01Mrz {

    private final byte[] rawData;
    private String name;
    private String surname;
    private String dateOfBirth;
    private String nationality;
    private String sex;
    private String dateOfExpiry;
    private String docNumber;
    private String docType;
    private String issuer;
    private String optData;
    private static final SimpleDateFormat SDFORMAT = new SimpleDateFormat("yyMMdd"); //$NON-NLS-1$
    private final Properties countryNames = new Properties();

    /** Sexo del titular del documento de identidad. */
    public enum Gender {

    	/** Hombre. */
    	MALE("Hombre"), //$NON-NLS-1$

    	/** Mujer. */
    	FEMALE("Mujer"); //$NON-NLS-1$

    	private final String desc;

    	private Gender(final String d) {
    		this.desc = d;
    	}

    	@Override
		public String toString() {
    		return this.desc;
    	}

    	static Gender getGender(final String text) {
    		if (text == null) {
    			throw new IllegalArgumentException("El texto de descripcion del sexo no puede ser nulo"); //$NON-NLS-1$
    		}
    		if ("F".equalsIgnoreCase(text.trim())) { //$NON-NLS-1$
    			return FEMALE;
    		}
    		if ("M".equalsIgnoreCase(text.trim())) { //$NON-NLS-1$
    			return MALE;
    		}
    		throw new IllegalArgumentException("Sexo indeterminado: " + text); //$NON-NLS-1$
    	}
    }


    /** Construye la zona ICAO MRZ del DNIe 3.0 a partir del fichero DG1.
     * @param rawBytes Contenido del fichero DG1 del DNIe 3.0.
     * @throws IOException Si no se encuentra la tabla de cosrrespondencias de pa&iacute;ses. */
    public Dnie3Dg01Mrz(final byte[] rawBytes) throws IOException {

    	this.countryNames.load(Dnie3Dg01Mrz.class.getResourceAsStream("/mrzcountrycodes.properties")); //$NON-NLS-1$

        this.rawData = rawBytes.clone();
        final byte[] mrzBytes = new byte[this.rawData[4]];
        System.arraycopy(this.rawData, 5, mrzBytes, 0, mrzBytes.length);
        final String mrzString = new String(mrzBytes);
        if (this.rawData[4] == 88) {
            final String mrz1 = mrzString.substring(0, 44);
            final String mrz2 = mrzString.substring(44, 88);
            this.docType = mrz1.substring(0, 2).replace('<', ' ').trim();
            this.issuer = mrz1.substring(2, 5).replace('<', ' ').trim();
            final String helpName = mrz1.substring(5, 44);
            for (int i = 0; i < helpName.length(); ++i) {
                if (helpName.charAt(i) != '<' || helpName.charAt(i + 1) != '<') {
					continue;
				}
                this.surname = helpName.substring(0, i).replace('<', ' ').trim();
                this.name = helpName.substring(i + 2).replace('<', ' ').trim();
                break;
            }
            this.docNumber = mrz2.substring(0, 9).replace('<', ' ').trim();
            this.nationality = mrz2.substring(10, 13).replace('<', ' ').trim();
            this.dateOfBirth = mrz2.substring(13, 19);
            this.sex = mrz2.substring(20, 21);
            this.dateOfExpiry = mrz2.substring(21, 27);
            this.optData = mrz2.substring(28, 42).replace('<', ' ').trim();
        }
        else {
            final String mrz1 = mrzString.substring(0, 30);
            final String mrz2 = mrzString.substring(30, 60);
            final String mrz3 = mrzString.substring(60, 90);
            this.docType = mrz1.substring(0, 2).replace('<', ' ').trim();
            this.issuer = mrz1.substring(2, 5).replace('<', ' ').trim();
            this.docNumber = mrz1.substring(5, 14).replace('<', ' ').trim();
            this.optData = mrz1.substring(15, 30).replace('<', ' ').trim();
            this.dateOfBirth = mrz2.substring(0, 6);
            this.sex = mrz2.substring(7, 8);
            this.dateOfExpiry = mrz2.substring(8, 14);
            this.nationality = mrz2.substring(15, 18).replace('<', ' ').trim();
            for (int i = 0; i < mrz3.length(); ++i) {
                if (mrz3.charAt(i) != '<' || mrz3.charAt(i + 1) != '<') {
					continue;
				}
                this.surname = mrz3.substring(0, i).replace('<', ' ').trim();
                this.name = mrz3.substring(i + 2).replace('<', ' ').trim();
                break;
            }
        }
    }

    /** Obtiene el contenido binario del fichero DG1 del DNIe 3.0.
     * @return Contenido binario del fichero DG1 del DNIe 3.0. */
    public byte[] getBytes() {
        return this.rawData.clone();
    }

    /** Obtiene el nombre del titular.
     * @return Nombre del titular. */
    public String getName() {
        return this.name;
    }

    /** Obtiene los apellidos del titular.
     * @return Apellidos del titular. */
    public String getSurname() {
        return this.surname;
    }

    /** Obtiene la fecha de nacimiento del titular.
     * @return Fecha de nacimiento del titular.
     * @throws ParseException Si la fecha encontrada en el fichero DG1 del DNIe 3.0 no est&aacute; en el formato esperado. */
    public Date getDateOfBirth() throws ParseException {
        return Dnie3Dg01Mrz.SDFORMAT.parse(this.dateOfBirth);
    }

    /** Obtiene la nacionalidad del titular.
     * @return Nacionalidad del titular. */
    public String getNationality() {
        final String c = this.countryNames.getProperty(this.nationality);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

    /** Obtiene el sexo del titular.
     * @return Sexo del titular. */
    public Gender getSex() {
    	return Gender.getGender(this.sex);
    }

    /** Obtiene la fecha de caducidad del DNIe 3.0.
     * @return Fecha de caducidad del DNIe 3.0.
     * @throws ParseException Si la fecha encontrada en el fichero DG1 del DNIe 3.0 no est&aacute; en el formato esperado. */
    public Date getDateOfExpiry() throws ParseException {
        return Dnie3Dg01Mrz.SDFORMAT.parse(this.dateOfExpiry);
    }

    /** Obtiene el n&uacute;mero del DNI.
     * @return N&uacute;mero del DNI. */
    public String getDocNumber() {
        return this.docNumber;
    }

    /** Obtiene el pa&iacute;s emisor del DNI.
     * @return Pa&iacute;s emisor del DNI. */
    public String getIssuer() {
        return this.countryNames.getProperty(this.issuer);
    }

    /** Obtiene datos adicionales del DNI.
     * @return Datos adicionales del DNI. */
    public String getOptData() {
        return this.optData;
    }

    /** Obtiene el tipo de documento de identidad.
     * @return Tipo de documento de identidad. */
    public String getDocType() {
        return this.docType;
    }
}

