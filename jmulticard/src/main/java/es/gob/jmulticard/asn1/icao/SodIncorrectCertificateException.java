package es.gob.jmulticard.asn1.icao;

/** Error de un certificado de firma del SOD incorrecto en formato.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SodIncorrectCertificateException extends SodException {

	SodIncorrectCertificateException(final String desc, final Exception cause) {
		super(desc, cause);
	}

	SodIncorrectCertificateException(final String desc) {
		super(desc);
	}

	private static final long serialVersionUID = -271661961400835155L;

}
