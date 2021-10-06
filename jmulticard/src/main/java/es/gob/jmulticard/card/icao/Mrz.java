package es.gob.jmulticard.card.icao;

import java.text.ParseException;
import java.util.Date;

/** MRZ de un MRTD ICAO.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface Mrz {

	/** Obtiene el nombre del titular.
     * @return Nombre del titular. */
    String getName();

    /** Obtiene los apellidos del titular.
     * @return Apellidos del titular. */
    String getSurname();

    /** Obtiene la fecha de nacimiento del titular.
     * @return Fecha de nacimiento del titular.
     * @throws ParseException Si la fecha encontrada no est&aacute; en el
     *         formato esperado. */
    Date getDateOfBirth() throws ParseException;

    /** Obtiene la nacionalidad del titular.
     * @return Nacionalidad del titular. */
    String getNationality();

    /** Obtiene el sexo del titular.
     * @return Sexo del titular. */
    Gender getSex();

    /** Obtiene la fecha de caducidad del MRTD.
     * @return Fecha de caducidad del MRTD.
     * @throws ParseException Si la fecha encontrada no est&aacute; en el formato esperado. */
    Date getDateOfExpiry() throws ParseException;

    /** Obtiene el n&uacute;mero de soporte del MRTD.
     * @return N&uacute;mero de soporte del MRTD. */
    String getDocNumber();

    /** Obtiene el pa&iacute;s emisor del MRTD.
     * @return Pa&iacute;s emisor del MRTD. */
    String getIssuer();

    /** Obtiene el n&uacute;mero del MRTD.
     * @return N&uacute;mero del MRTD. */
    String getSubjectNumber();

    /** Obtiene el tipo de MRTD.
     * @return Tipo de MRTD. */
    String getDocType();

}
