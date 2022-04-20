package es.gob.jmulticard;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** Utilidad de generaci&oacute;n de certificados.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CertificateUtils {

	/** Factor&iacute;a para la creaci&oacute;n de certificados. */
	private static final CertificateFactory CF;
	static {
		try {
			CF = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		}
		catch(final Exception e3) {
			throw new IllegalStateException(
				"No se puede instanciar la factoria de certificados X.509: " + e3, e3 //$NON-NLS-1$
			);
		}
	}

	private CertificateUtils() {
		// No instanciable
	}

	/** Genera un certificado a partir de su codificaci&oacute;n binaria.
	 * @param encoded Codificaci&oacute;n binaria del certificado.
	 * @return Certificado.
	 * @throws CertificateException Si la codificaci&oacute;n binaria no correspond&iacute;a a un
	 *                              certificado. */
	public static X509Certificate generateCertificate(final byte[] encoded) throws CertificateException {
		return generateCertificate(new ByteArrayInputStream(encoded));
	}

	/** Genera un certificado a partir de un flujo hacia su codificaci&oacute;n binaria.
	 * @param is Flujo de lectura hacia la Codificaci&oacute;n binaria del certificado.
	 * @return Certificado.
	 * @throws CertificateException Si la codificaci&oacute;n binaria no correspond&iacute;a a un
	 *                              certificado o no se pudo leer del flujo de entrada. */
	public static X509Certificate generateCertificate(final InputStream is) throws CertificateException {
		return (X509Certificate) CF.generateCertificate(is);
	}

}
