package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;

/** Funciones comunes a un PrKDF.
 * Necesario para acomodar PrKDF que no se adec&uacute;en por completo al PrKDF especificado en PKCS#15,
 * para tener de esta manera todas las implementanciones un ancestro com&uacute;n con todos los
 * m&eacute;todos.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface Pkcs15PrKdf {

    /** Establece el valor (en codificaci&oacute;n DER) del objeto ASN&#46;1.
     * @param value Valor (TLC con codificaci&oacute;n DER) del objeto ASN&#46;1.
     * @throws Asn1Exception Si no se puede decodificar adecuadamente el valor establecido.
     * @throws TlvException Si hay errores relativos a los TLV DER al decodificar los datos de entrada. */
    void setDerValue(final byte[] value) throws Asn1Exception, TlvException;

	/** Obtiene el n&uacute;mero de claves del PrKDF.
	 * @return N&uacute;mero de claves del PrKDF */
	int getKeyCount();

	/** Obtiene el identificador de la clave indicada.
	 * @param index &Iacute;ndice de la clave.
	 * @return Identificador de la clave indicada. */
	byte[] getKeyId(final int index);

	/** Obtiene la referencia de la clave indicada.
	 * @param index &Iacute;ndice de la clave.
	 * @return Referencia de la clave indicada. */
	byte getKeyReference(final int index);

}
