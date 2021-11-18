package es.gob.jmulticard.card.dnie;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.card.icao.Gender;

/** Identidad del titular tal y como se encuentra en el fichero DG13 de un DNIe. */
public final class OptionalDetailsDnie3 extends OptionalDetails {

	/** Identifica los pares de control 0x00-0x1F y 0x7F-0x9F). */
	private static final Pattern CONTROL_CHARACTER_WORD = Pattern.compile("\\p{Cc}{2}"); //$NON-NLS-1$

	private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd MM yyyy"); //$NON-NLS-1$

	private static final byte TAG = 0x6D;

	private String[] parsedValues = null;

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

	/** Obtiene el n&uacute;mero de documento del titular.
	 * @return N&uacute;mero de documento del titular. */
	public String getDniNumber() {
		return this.parsedValues[4];
	}

	/** Obtiene la fecha de nacimiento del titular.
	 * @return Fecha de nacimiento del titular.
	 * @throws ParseException Si la fecha encontrada no est&aacute; en el formato esperado. */
	public Date getBirthDate() throws ParseException {
		return DATE_FORMAT.parse(this.parsedValues[5]);
	}

	/** Obtiene la nacionalidad del titular.
	 * @return Nacionalidad del titular. */
	public String getNationality() {
		return this.parsedValues[6];
	}

	/** Obtiene la fecha de caducidad del DNIe.
	 * @return Fecha de caducidad del DNIe.
	 * @throws ParseException Si la fecha encontrada no est&aacute; en el formato esperado. */
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
	public Gender getSex() {
		return Gender.getGender(this.parsedValues[9]);
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

	/** Obtiene los nombres de los padres del titular.
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

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		checkTag(getBytes()[0]);
		this.parsedValues = new String(getRawDerValue()).split(CONTROL_CHARACTER_WORD.pattern());
	}

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

	@Override
	public String toString() {
		String birthDate;
		try {
			birthDate = DATE_FORMAT.format(getBirthDate());
		}
		catch (final ParseException e) {
			birthDate = "Error: " + e; //$NON-NLS-1$
		}
		String expirationDate;
		try {
			expirationDate = DATE_FORMAT.format(getExpirationDate());
		}
		catch (final ParseException e) {
			expirationDate = "Error: " + e; //$NON-NLS-1$
		}
		return
			"Detalles opcionales (DG13):\n" + //$NON-NLS-1$
			"  Nombre del titular: " + getName() + '\n' + //$NON-NLS-1$
			"  Primer apellido del titular: " + getFirstSurname() + '\n' + //$NON-NLS-1$
			"  Segundo apellido del titular: " + getSecondSurname() + '\n' + //$NON-NLS-1$
			"  Numero del DNI del titular: " + getDniNumber() + '\n' + //$NON-NLS-1$
			"  Nacionalidad del titular: " + getNationality() +  '\n' + //$NON-NLS-1$
			"  Fecha de nacimiento del titular: " + birthDate + '\n' + //$NON-NLS-1$
			"  Ciudad de nacimiento del titular: " + getBirthCity() + '\n' + //$NON-NLS-1$
			"  Pais de nacimiento del titular: " + getBirthCountry() + '\n' + //$NON-NLS-1$
			"  Nombres de los padres del titular: " + getParentsNames() + '\n' + //$NON-NLS-1$
			"  Sexo del titular: " + getSex() +  '\n' + //$NON-NLS-1$
			"  Direccion de residencia del titular: " + getAddress() + '\n' + //$NON-NLS-1$
			"  Ciudad de residencia del titular: " + getCity() + '\n' + //$NON-NLS-1$
			"  Provincia de residencia del titular: " + getProvince() + '\n' + //$NON-NLS-1$
			"  Pais de residencia del titular: " + getCountry() + '\n' + //$NON-NLS-1$
			"  Fecha de caducidad del DNI: " + expirationDate + '\n' + //$NON-NLS-1$
			"  Numero de soporte del DNI: " + getSupportNumber() + '\n'; //$NON-NLS-1$
	}

}
