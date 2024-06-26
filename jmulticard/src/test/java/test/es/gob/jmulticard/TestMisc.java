package test.es.gob.jmulticard;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import es.gob.jmulticard.asn1.der.x509.SubjectDirectoryAttributes;
import es.gob.jmulticard.card.dnie.DnieCertParseUtil;

/** Pruebas varias.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestMisc {

	/** Prueba la obtenci&oacute;n de datos del titular a partir de un certificado de DNIe.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testCertParsing() throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		final X509Certificate cert;
		try (InputStream is = TestMisc.class.getResourceAsStream("/DNICERT.cer")) { //$NON-NLS-1$
			cert = (X509Certificate) cf.generateCertificate(is);
		}
		System.out.println(new DnieCertParseUtil(cert));
	}

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		final X509Certificate cert;
		try (InputStream is = TestMisc.class.getResourceAsStream("/DNICERT.cer")) { //$NON-NLS-1$
			cert = (X509Certificate) cf.generateCertificate(is);
		}
		final byte[] subjectDirAttrsBytes = cert.getExtensionValue("2.5.29.9"); //$NON-NLS-1$
//		System.out.println(new String(subjectDirAttrsBytes));
//		try (final OutputStream fos = new FileOutputStream(File.createTempFile("SubjectDirectoryAttributes_", ".asn1"))) { //$NON-NLS-1$ //$NON-NLS-2$
//			fos.write(subjectDirAttrsBytes);
//		}
		final SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes();
		sda.setDerValue(subjectDirAttrsBytes);
		System.out.println(sda);
		System.out.println(sda.getSubjectBirthDate());
	}
}
