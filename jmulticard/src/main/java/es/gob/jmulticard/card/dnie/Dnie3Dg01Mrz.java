
package es.gob.jmulticard.card.dnie;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import es.gob.jmulticard.card.icao.CountryCodes;
import es.gob.jmulticard.card.icao.Gender;
import es.gob.jmulticard.card.icao.Mrz;

/** ICAO MRZ del DNIe 3&#46;0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Dnie3Dg01Mrz implements Mrz {

    private static final SimpleDateFormat SDFORMAT = new SimpleDateFormat("yyMMdd"); //$NON-NLS-1$

	private transient final String mrzString;
    private final byte[] rawData;

    private transient String name;
    private transient String surname;
    private transient String dateOfBirth;
    private transient String nationality;
    private transient String sex;
    private transient String dateOfExpiry;
    private transient String docNumber;
    private transient String docType;
    private transient String issuer;
    private transient String optData;

    /** Construye la ICAO MRZ del DNIe 3&#46;0 a partir del fichero DG1.
     * @param rawBytes Contenido del fichero DG1 del DNIe 3&#46;0. */
    Dnie3Dg01Mrz(final byte[] rawBytes) {

        rawData = rawBytes.clone();
        final byte[] mrzBytes = new byte[rawData[4]];
        System.arraycopy(rawData, 5, mrzBytes, 0, mrzBytes.length);
        mrzString = new String(mrzBytes);
        if (rawData[4] == 88) {
            final String mrz1 = mrzString.substring(0, 44);
            final String mrz2 = mrzString.substring(44, 88);
            docType = mrz1.substring(0, 2).replace('<', ' ').trim();
            issuer = mrz1.substring(2, 5).replace('<', ' ').trim();
            final String helpName = mrz1.substring(5, 44);
            for (int i = 0; i < helpName.length(); ++i) {
                if (helpName.charAt(i) != '<' || helpName.charAt(i + 1) != '<') {
					continue;
				}
                surname = helpName.substring(0, i).replace('<', ' ').trim();
                name = helpName.substring(i + 2).replace('<', ' ').trim();
                break;
            }
            docNumber = mrz2.substring(0, 9).replace('<', ' ').trim();
            nationality = mrz2.substring(10, 13).replace('<', ' ').trim();
            dateOfBirth = mrz2.substring(13, 19);
            sex = mrz2.substring(20, 21);
            dateOfExpiry = mrz2.substring(21, 27);
            optData = mrz2.substring(28, 42).replace('<', ' ').trim();
        }
        else {
            final String mrz1 = mrzString.substring(0, 30);
            final String mrz2 = mrzString.substring(30, 60);
            final String mrz3 = mrzString.substring(60, 90);
            docType = mrz1.substring(0, 2).replace('<', ' ').trim();
            issuer = mrz1.substring(2, 5).replace('<', ' ').trim();
            docNumber = mrz1.substring(5, 14).replace('<', ' ').trim();
            optData = mrz1.substring(15, 30).replace('<', ' ').trim();
            dateOfBirth = mrz2.substring(0, 6);
            sex = mrz2.substring(7, 8);
            dateOfExpiry = mrz2.substring(8, 14);
            nationality = mrz2.substring(15, 18).replace('<', ' ').trim();
            for (int i = 0; i < mrz3.length(); ++i) {
                if (mrz3.charAt(i) != '<' || mrz3.charAt(i + 1) != '<') {
					continue;
				}
                surname = mrz3.substring(0, i).replace('<', ' ').trim();
                name = mrz3.substring(i + 2).replace('<', ' ').trim();
                break;
            }
        }
    }

    @Override
	public String toString() {
    	return mrzString;
    }

    /** Obtiene el contenido binario del fichero DG1 del DNIe 3&#46;0.
     * @return Contenido binario del fichero DG1 del DNIe 3&#46;0. */
    @Override
	public byte[] getBytes() {
        return rawData.clone();
    }

    @Override
	public String getName() {
        return name;
    }

    @Override
	public String getSurname() {
        return surname;
    }

    @Override
	public Date getDateOfBirth() throws ParseException {
        return SDFORMAT.parse(dateOfBirth);
    }

    @Override
	public String getNationality() {
        final String c = CountryCodes.getCountryName(nationality);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

    @Override
	public Gender getSex() {
    	return Gender.getGender(sex);
    }

    @Override
	public synchronized Date getDateOfExpiry() throws ParseException {
        return SDFORMAT.parse(dateOfExpiry);
    }

    @Override
	public String getDocNumber() {
        return docNumber;
    }

    @Override
	public String getIssuer() {
    	final String c = CountryCodes.getCountryName(issuer);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

    @Override
	public String getSubjectNumber() {
        return optData;
    }

    @Override
	public String getDocType() {
        return docType;
    }

    /** Obtiene el contenido binario directo del objeto DG01.
     * @return Contenido binario directo del objeto DG01. */
    public byte[] getRawData() {
        return rawData.clone();
    }
}
