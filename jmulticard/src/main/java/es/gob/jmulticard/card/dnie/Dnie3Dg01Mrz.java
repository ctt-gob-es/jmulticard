
package es.gob.jmulticard.card.dnie;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import es.gob.jmulticard.card.icao.CountryCodes;
import es.gob.jmulticard.card.icao.Gender;
import es.gob.jmulticard.card.icao.Mrz;

/** ICAO MRZ del DNIe 3&#46;0.*/
public final class Dnie3Dg01Mrz implements Mrz {

    private static final SimpleDateFormat SDFORMAT = new SimpleDateFormat("yyMMdd"); //$NON-NLS-1$

	private final String mrzString;
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

    /** Construye la ICAO MRZ del DNIe 3&#46;0 a partir del fichero DG1.
     * @param rawBytes Contenido del fichero DG1 del DNIe 3&#46;0. */
    Dnie3Dg01Mrz(final byte[] rawBytes) {

        this.rawData = rawBytes.clone();
        final byte[] mrzBytes = new byte[this.rawData[4]];
        System.arraycopy(this.rawData, 5, mrzBytes, 0, mrzBytes.length);
        this.mrzString = new String(mrzBytes);
        if (this.rawData[4] == 88) {
            final String mrz1 = this.mrzString.substring(0, 44);
            final String mrz2 = this.mrzString.substring(44, 88);
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
            final String mrz1 = this.mrzString.substring(0, 30);
            final String mrz2 = this.mrzString.substring(30, 60);
            final String mrz3 = this.mrzString.substring(60, 90);
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

    @Override
	public String toString() {
    	return this.mrzString;
    }

    /** Obtiene el contenido binario del fichero DG1 del DNIe 3&#46;0.
     * @return Contenido binario del fichero DG1 del DNIe 3&#46;0. */
    @Override
	public byte[] getBytes() {
        return this.rawData.clone();
    }

    @Override
	public String getName() {
        return this.name;
    }

    @Override
	public String getSurname() {
        return this.surname;
    }

    @Override
	public Date getDateOfBirth() throws ParseException {
        return SDFORMAT.parse(this.dateOfBirth);
    }

    @Override
	public String getNationality() {
        final String c = CountryCodes.getCountryName(this.nationality);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

    @Override
	public Gender getSex() {
    	return Gender.getGender(this.sex);
    }

    @Override
	public synchronized Date getDateOfExpiry() throws ParseException {
        return SDFORMAT.parse(this.dateOfExpiry);
    }

    @Override
	public String getDocNumber() {
        return this.docNumber;
    }

    @Override
	public String getIssuer() {
    	final String c = CountryCodes.getCountryName(this.issuer);
        return c != null ? c : "Desconocido"; //$NON-NLS-1$
    }

    @Override
	public String getSubjectNumber() {
        return this.optData;
    }

    @Override
	public String getDocType() {
        return this.docType;
    }

    /** Obtiene el contenido binario directo del objeto DG01.
     * @return Contenido binario directo del objeto DG01. */
    public byte[] getRawData() {
        return this.rawData.clone();
    }
}
