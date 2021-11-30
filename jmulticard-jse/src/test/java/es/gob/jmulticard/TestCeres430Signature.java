package es.gob.jmulticard;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

import org.junit.Ignore;
import org.junit.Test;
import org.spongycastle.util.encoders.Base64;

import es.gob.jmulticard.jse.provider.Ceres430Provider;

/** Pruebas de firma en tarjeta CERES v4.30. */
public class TestCeres430Signature {

	private static final String PROVIDER_NAME = "CERES430"; //$NON-NLS-1$
	private static final String ALGORITHM = "SHA256withRSA"; //$NON-NLS-1$
	private static final byte[] DATA = "Datos a firmar".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
	private static final char[] PASSWORD = "1234".toCharArray(); //$NON-NLS-1$

	/** Prueba de firmas consecutivas.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testSignRepeatedly() throws Exception {

    	Security.addProvider(new Ceres430Provider());

    	final KeyStore ks = KeyStore.getInstance(PROVIDER_NAME);
    	ks.load(null, PASSWORD);
    	final String alias = ks.aliases().nextElement();
    	final PrivateKey sKey = (PrivateKey) ks.getKey(alias, PASSWORD);

    	final Signature signature1 = Signature.getInstance(ALGORITHM);
    	signature1.initSign(sKey);
    	signature1.update(DATA);

    	System.out.println( "Firma 1: " + Base64.toBase64String(signature1.sign())); //$NON-NLS-1$

    	final Signature signature2 = Signature.getInstance(ALGORITHM);
    	signature2.initSign(sKey);
    	signature2.update(DATA);

    	System.out.println( "Firma 2: " + Base64.toBase64String(signature2.sign())); //$NON-NLS-1$
	}
}
