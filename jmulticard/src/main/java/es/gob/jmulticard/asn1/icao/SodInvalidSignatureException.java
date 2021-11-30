package es.gob.jmulticard.asn1.icao;

/** Error de validez de la firma del SOD.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SodInvalidSignatureException extends SodException {

	SodInvalidSignatureException(final String desc) {
		super(desc);
	}

	SodInvalidSignatureException(final String desc, final Exception cause) {
		super(desc, cause);
	}

	private static final long serialVersionUID = -271661961400835155L;

}
