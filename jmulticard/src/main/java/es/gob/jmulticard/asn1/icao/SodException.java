package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.asn1.Asn1Exception;

/** Error en el tratamiento o an&aacute;lisis del SOD.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class SodException extends Asn1Exception {

	SodException(final String desc, final Exception cause) {
		super(desc, cause);
	}

	SodException(final String desc) {
		super(desc);
	}

	private static final long serialVersionUID = -4239444108089498852L;

}
