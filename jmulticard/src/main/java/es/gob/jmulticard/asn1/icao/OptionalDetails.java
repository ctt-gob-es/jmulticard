package es.gob.jmulticard.asn1.icao;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.card.icao.Gender;

/** Detalles opcionales de un eMRTD contenidos en el DG13.
 * La implementaci&oacute;n de este grupo de datos depende por completo del eMRTD, pero
 * en esta implementaci&oacute;n se proporcionan m&eacute;todos para obtener los
 * campos de la implementaci&oacute;n del DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class OptionalDetails extends DecoderObject {

	private static final byte TAG = 0x6D;

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

	/** Identifica los pares de control 0x00-0x1F y 0x7F-0x9F). */
	private static final Pattern CONTROL_CHARACTER_WORD = Pattern.compile("\\p{Cc}{2}"); //$NON-NLS-1$

	private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd MM yyyy"); //$NON-NLS-1$

	/** Pa&iacute;s "ESPA&Ntilde;A". */
	public static final String SPAIN = "ESPA\u00D1A"; //$NON-NLS-1$

	private static final List<String> SPANISH_PROVINCES = Arrays.asList(
		"ARABA/ALAVA",            "ALBACETE",  "ALICANTE-ALACANT", "ALMERIA",           "ASTURIAS",      //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"AVILA",                  "BADAJOZ",   "BARCELONA",        "BURGOS",            "CACERES",       //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"CADIZ",                  "CANTABRIA", "CIUDAD REAL",      "CORDOBA",           "A CORU\u00D1A", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"CUENCA",                 "GIRONA",    "GRANADA",          "GUADALAJARA",       "GIPUZKOA",      //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"HUELVA",                 "HUESCA",    "ILLES BALEARS",    "JAEN",              "LEON",          //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"LLEIDA",                 "LUGO",      "MADRID",           "MALAGA",            "MURCIA",        //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"NAVARRA",                "OURENSE",   "PALENCIA",         "LAS PALMAS",        "PONTEVEDRA",    //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"LA RIOJA",               "SEGOVIA",   "SEVILLA",          "SORIA",             "TARRAGONA",     //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"SANTA CRUZ DE TENERIFE", "TERUEL",    "TOLEDA",           "VALENCIA-VALENCIA", "VALLADOLID",    //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		"BIZKAIA",                "ZAMORA",    "ZARAGOZA",         "CEUTA",             "MELILLA"        //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
	);

	private String[] parsedValues = null;

	/** Obtiene el nombre del titular.
	 * @return Nombre del titular. */
	public String getName() {
		if (parsedValues != null && parsedValues.length > 3) {
			return parsedValues[3]; // Nombre
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene el primer apellido del titular.
	 * @return Primer apellido del titular. */
	public String getSecondSurname() {
		if (parsedValues != null && parsedValues.length > 2) {
			return parsedValues[2]; // Segundo apellido
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene el segundo apellido del titular.
	 * @return Segundo apellido del titular. */
	public String getFirstSurname() {
		if (parsedValues != null && parsedValues.length > 1) {
			return parsedValues[1]; // Primer apellido

		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene el n&uacute;mero de documento del titular.
	 * @return N&uacute;mero de documento del titular. */
	public String getIdNumber() {
		if (parsedValues != null && parsedValues.length > 4) {
			return parsedValues[4];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene la fecha de nacimiento del titular.
	 * @return Fecha de nacimiento del titular.
	 * @throws ParseException Si la fecha encontrada no est&aacute; en el formato esperado. */
	public synchronized Date getBirthDate() throws ParseException {
		if (parsedValues != null && parsedValues.length > 5) {
			return dateFormat.parse(parsedValues[5]);
		}
		return new Date();
	}

	/** Obtiene la nacionalidad del titular.
	 * @return Nacionalidad del titular. */
	public String getNationality() {
		if (parsedValues != null && parsedValues.length > 6) {
			return parsedValues[6];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene la fecha de caducidad del DNIe.
	 * @return Fecha de caducidad del DNIe.
	 * @throws ParseException Si la fecha encontrada no est&aacute; en el formato esperado. */
	public Date getExpirationDate() throws ParseException {
		if (parsedValues != null && parsedValues.length > 7) {
			return dateFormat.parse(parsedValues[7]);
		}
		return new Date();
	}

	/** Obtiene el n&uacute;mero de soporte del DNIe.
	 * @return N&uacute;mero de soporte del DNIe. */
	public String getSupportNumber() {
		if (parsedValues != null && parsedValues.length > 7) {
			return parsedValues[8];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene el sexo del titular.
	 * @return Sexo del titular. */
	public Gender getSex() {
		if (parsedValues != null && parsedValues.length > 9) {
			return Gender.getGender(parsedValues[9]);
		}
		return Gender.OTHER;
	}

	/** Obtiene la ciudad de nacimiento del titular.
	 * @return Ciudad de nacimiento del titular. */
	public String getBirthCity() {
		if (parsedValues != null && parsedValues.length > 10) {
			return parsedValues[10];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene la provincia de nacimiento del titular.
	 * @return Provincia de nacimiento del titular. */
	public String getBirthProvince() {
		if (parsedValues != null && parsedValues.length > 11) {
			if (SPANISH_PROVINCES.contains(parsedValues[11].toUpperCase())) {
				return parsedValues[11];
			}
			return parsedValues[10];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene el pa&iacute;s de nacimiento del titular.
	 * @return Pa&iacute;s de nacimiento del titular. */
	public String getBirthCountry() {
		if (parsedValues != null && parsedValues.length > 11) {
			if (SPANISH_PROVINCES.contains(parsedValues[11].toUpperCase())) {
				return SPAIN;
			}
			return parsedValues[11];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene los nombres de los padres del titular.
	 * @return Nombres de los padres del titular. */
	public String getParentsNames() {
		if (parsedValues != null && parsedValues.length > 12) {
			return parsedValues[12];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene la direcci&oacute;n de residencia del titular.
	 * @return Direcci&oacute;n de residencia del titular. */
	public String getAddress() {
		if (parsedValues != null && parsedValues.length > 13) {
			return parsedValues[13];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene la ciudad de residencia del titular.
	 * @return Ciudad de residencia del titular. */
	public String getCity() {
		if (parsedValues != null && parsedValues.length > 14) {
			return parsedValues[14];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene el pa&iacute;s de residencia del titular.
	 * @return Pa&iacute;s de residencia del titular. */
	public String getCountry() {
		if (parsedValues != null && parsedValues.length > 16) {
			if (SPANISH_PROVINCES.contains(parsedValues[16].toUpperCase())) {
				return SPAIN;
			}
			return parsedValues[16];
		}
		return ""; //$NON-NLS-1$
	}

	/** Obtiene la provincia de residencia del titular.
	 * @return Provincia de residencia del titular. */
	public String getProvince() {
		if (parsedValues != null && parsedValues.length > 16) {
		    if (!parsedValues[15].isEmpty()) {
		    	return parsedValues[15];
		    }
		    return parsedValues[16];
		}
		return ""; //$NON-NLS-1$
	}

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		checkTag(getBytes()[0]);
		try {
			parsedValues = new String(getBytes()).split(CONTROL_CHARACTER_WORD.pattern());
		}
		catch(final Exception e) {
			JmcLogger.warning("El DG13 esta en un formato no soportado: " + e); //$NON-NLS-1$
		}
	}

	@Override
	public String toString() {
		String birthDate;
		try {
			birthDate = dateFormat.format(getBirthDate());
		}
		catch (final ParseException e) {
			birthDate = "Error: " + e; //$NON-NLS-1$
		}
		String expirationDate;
		try {
			expirationDate = dateFormat.format(getExpirationDate());
		}
		catch (final ParseException e) {
			expirationDate = "Error: " + e; //$NON-NLS-1$
		}
		return
			"Detalles opcionales (DG13):\n" + //$NON-NLS-1$
			"  Nombre del titular: "                  + getName()          + '\n' + //$NON-NLS-1$
			"  Primer apellido del titular: "         + getFirstSurname()  + '\n' + //$NON-NLS-1$
			"  Segundo apellido del titular: "        + getSecondSurname() + '\n' + //$NON-NLS-1$
			"  Numero del DNI del titular: "          + getIdNumber()      + '\n' + //$NON-NLS-1$
			"  Nacionalidad del titular: "            + getNationality()   + '\n' + //$NON-NLS-1$
			"  Fecha de nacimiento del titular: "     + birthDate          + '\n' + //$NON-NLS-1$
			"  Ciudad de nacimiento del titular: "    + getBirthCity()     + '\n' + //$NON-NLS-1$
			"  Provincia de nacimiento del titular: " + getBirthProvince() + '\n' + //$NON-NLS-1$
			"  Pais de nacimiento del titular: "      + getBirthCountry()  + '\n' + //$NON-NLS-1$
			"  Nombres de los padres del titular: "   + getParentsNames()  + '\n' + //$NON-NLS-1$
			"  Sexo del titular: "                    + getSex()           + '\n' + //$NON-NLS-1$
			"  Direccion de residencia del titular: " + getAddress()       + '\n' + //$NON-NLS-1$
			"  Ciudad de residencia del titular: "    + getCity()          + '\n' + //$NON-NLS-1$
			"  Provincia de residencia del titular: " + getProvince()      + '\n' + //$NON-NLS-1$
			"  Pais de residencia del titular: "      + getCountry()       + '\n' + //$NON-NLS-1$
			"  Fecha de caducidad del DNI: "          + expirationDate     + '\n' + //$NON-NLS-1$
			"  Numero de soporte del DNI: "           + getSupportNumber(); //$NON-NLS-1$
	}
}
