package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;

/** Funciones comunes a un CDF.
 * Necesario para acomodar CDF que no se adec&uacute;en por completo al CDF especificado en PKCS#15,
 * para tener de esta manera todas las implementanciones un ancestro com&uacute;n con todos los
 * m&eacute;todos.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface Pkcs15Cdf {

	/** Obtiene el n&uacute;mero de certificados del CDF.
     * @return N&uacute;mero de certificados del CDF */
    int getCertificateCount();

    /** Obtiene la ruta PKCS#15 hacia el certificado indicado.
     * @param index &Iacute;ndice del certificado.
     * @return Ruta PKCS#15 hacia el certificado indicado. */
    String getCertificatePath(final int index);

    /** Obtiene el identificador del certificado indicado.
     * @param index &Iacute;ndice del certificado.
     * @return Identificador del certificado indicado. */
    byte[] getCertificateId(final int index);

    /** Establece el valor (en codificaci&oacute;n DER) del objeto ASN&#46;1.
     * @param value Valor (TLC con codificaci&oacute;n DER) del objeto ASN&#46;1.
     * @throws Asn1Exception Si no se puede decodificar adecuadamente el valor establecido.
     * @throws TlvException Si hay errores relativos a los TLV DER al decodificar los datos de entrada. */
    void setDerValue(final byte[] value) throws Asn1Exception, TlvException;

}
