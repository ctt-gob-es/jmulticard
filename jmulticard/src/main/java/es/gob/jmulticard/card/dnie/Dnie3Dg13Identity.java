package es.gob.jmulticard.card.dnie;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

/** Identidad del titular tal y como se encuentra en el fichero DG13 del DNIe 3. */
public class Dnie3Dg13Identity {

	/** This regEx matches on every pair (word) of control character (0x00-0x1F and
	 * 0x7F-0x9F). */
	private static final Pattern CONTROL_CHARACTER_WORD = Pattern.compile("\\p{Cc}{2}"); //$NON-NLS-1$

	private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd MM yyyy"); //$NON-NLS-1$

	private final String[] parsedValues;

	Dnie3Dg13Identity(final byte[] dg13RawData) {
		this.parsedValues = new String(dg13RawData).split(CONTROL_CHARACTER_WORD.pattern());
	}

	/** Obtiene el nombre del titular.
	 * @return Nombre del titular. */
	public String getName() {
		return this.parsedValues[3]; // Nombre
	}

	/** Obtiene el primer apellido del titular.
	 * @return Primer apellido del titular. */
	public String getSecondSurname() {
		return this.parsedValues[2]; // Segundo apellido
	}

	/** Obtiene el segundo apellido del titular.
	 * @return Segundo apellido del titular. */
	public String getFirstSurname() {
		return this.parsedValues[1]; // Primer apellido
	}

	/** Obtiene el n&uacute;mero de DNI del titular.
	 * @return N&uacute;mero de DNI del titular. */
	public String getDniNumber() {
		return this.parsedValues[4];
	}

	/** Obtiene la fecha de nacimiento del titular.
	 * @return Fecha de nacimiento del titular.
	 * @throws ParseException Si la fecha encontrada en el DNIe no est&aacute; en el formato esperado. */
	public Date getBirthDate() throws ParseException {
		return DATE_FORMAT.parse(this.parsedValues[5]);
	}

	/** Obtiene la nacionalidad del titular.
	 * @return Nacionalidad del titular. */
	public String getNationality() {
		return this.parsedValues[6];
	}

	/** Obtiene la fecha de caducidad del DNIe.
	 * @return Fecha de caducidad del DNIe
	 * @throws ParseException Si la fecha encontrada en el DNIe no est&aacute; en el formato esperado. */
	public Date getExpirationDate() throws ParseException {
		return DATE_FORMAT.parse(this.parsedValues[7]);
	}

	/** Obtiene el n&uacute;mero de soporte del DNIe.
	 * @return N&uacute;mero de soporte del DNIe. */
	public String getSupportNumber() {
		return this.parsedValues[8];
	}

	/** Obtiene el sexo del titular.
	 * @return Sexo del titular. */
	public Dnie3Dg01Mrz.Gender getSex() {
		return Dnie3Dg01Mrz.Gender.getGender(this.parsedValues[9]);
	}

	/** Obtiene la ciudad de nacimiento del titular.
	 * @return Ciudad de nacimiento del titular. */
	public String getBirthCity() {
		return this.parsedValues[10];
	}

	/** Obtiene el pa&iacute;s de nacimiento del titular.
	 * @return Pa&iacute;s de nacimiento del titular. */
	public String getBirthCountry() {
		return this.parsedValues[11];
	}

	/** Obtien los nombres de los padres del titular.
	 * @return Nombres de los padres del titular. */
	public String getParentsNames() {
		return this.parsedValues[12];
	}

	/** Obtiene la direcci&oacute;n de residencia del titular.
	 * @return Direcci&oacute;n de residencia del titular. */
	public String getAddress() {
		return this.parsedValues[13];
	}

	/** Obtiene la ciudad de residencia del titular.
	 * @return Ciudad de residencia del titular. */
	public String getCity() {
		return this.parsedValues[14];
	}

	/** Obtiene el pa&iacute;s de residencia del titular.
	 * @return Pa&iacute;s de residencia del titular. */
	public String getCountry() {
		return this.parsedValues[16];
	}

	/** Obtiene la provincia de residencia del titular.
	 * @return Provincia de residencia del titular. */
	public String getProvince() {
	    return this.parsedValues[15];
	}

}
