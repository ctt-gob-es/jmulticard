package es.gob.jmulticard;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/** Reimplementaci&oacute;n de funcionalidades que con su codificaci&oacute;n
 * normal no traducen adecuadamente con <i>J2Obc</i>.
 * Estas funcionaliades deber&iacute;n revisarse peri&oacute;dicamente
 * seg&uacute;n aparezcan nuevas versiones de <i>J2Obc</i>, para volver a las
 * codificaciones normales.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface TranslationHelper {

	/** Obtiene una clave privada RSA de un certificado X&#46;509.
	 * @param cert Certificado X&#46;509, debe ser de tipo RSA.
	 * @return Clave privada RSA del certificado X&#46;509.
	 * @throws CertificateEncodingException Si el certificado proporcionado
	 *                                      no es v&aacute;lido. */
	RSAPublicKey getRSAPublicKeyFromCert(X509Certificate cert) throws CertificateEncodingException;
}
