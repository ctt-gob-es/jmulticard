package es.gob.jmulticard.asn1.icao;

import java.security.cert.CertificateException;

/** Error de un certificado de firma del SOD caducado o a&uacute;n
 * no v&aacute;lido.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SodInvalidCertificateException extends SodException {

	SodInvalidCertificateException(final String desc, final CertificateException cause) {
		super(desc, cause);
	}

	private static final long serialVersionUID = -271661961400835155L;

}
