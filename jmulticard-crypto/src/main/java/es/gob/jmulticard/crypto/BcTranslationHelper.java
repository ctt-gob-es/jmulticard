package es.gob.jmulticard.crypto;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import es.gob.jmulticard.TranslationHelper;

public class BcTranslationHelper implements TranslationHelper {

	BcTranslationHelper() {
		// Vacio
	}

	@Override
	public RSAPublicKey getRSAPublicKeyFromCert(final X509Certificate cert) throws CertificateEncodingException {
//		if (cert == null) {
//			throw new IllegalArgumentException(
//				"El certificado del cual extraer la clave publica no puede ser nulo" //$NON-NLS-1$
//			);
//		}
//		final byte[] certBytes = cert.getEncoded();
//
//		final RSAPublicKeySpec spec = new RSAPublicKeySpec(
//			null, // modulus,
//			null  // exponent
//		);
//		final KeyFactory factory = KeyFactory.getInstance("RSA");
//		final PublicKey pub = factory.generatePublic(spec);
		return null;
	}

}
