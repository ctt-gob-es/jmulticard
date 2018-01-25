package es.gob.jmulticard;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import javax.security.auth.callback.PasswordCallback;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.bit4id.stcm.StCard;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de la tajeta de <a href="http://www.bit4id.com/">Bit4Id</a> con chip <a href="http://www.st.com/">ST</a>
 *  distribuida por <a href="http://www.camerfirma.com/">CamerFirma</a>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestStBit4IdCamerfirma {

	private static final String PIN =  "12345678"; //$NON-NLS-1$

	/** Prueba general de la tarjeta.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {

		final ApduConnection conn = new SmartcardIoConnection();
		final StCard card = new StCard(conn);
		card.verifyPin(new CachePasswordCallback(PIN.toCharArray()));

	}

	/** Prueba de an&aacute;lisis del fichero 2F:FF:00:00.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void test0000() throws Exception {
		final byte[] data = AOUtil.getDataFromInputStream(
			TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/0000_7076199932780544215.DER.txt") //$NON-NLS-1$
		);
		System.out.println(HexUtils.hexify(data, true));
	}

	/** Prueba de an&aacute;lisis del fichero 2F:FF:80:28.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void test8028() throws Exception {
		final byte[] data = AOUtil.getDataFromInputStream(
			TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/8028_6486727951599148607.DER.txt") //$NON-NLS-1$
		);
		System.out.println(HexUtils.hexify(data, true));
		final byte[] trimmedData = new byte[data.length-9];
		System.arraycopy(data, 9, trimmedData, 0, trimmedData.length);
		System.out.println();
		System.out.println();
		System.out.println(HexUtils.hexify(trimmedData, true));

		try (
			final OutputStream fos = new FileOutputStream(File.createTempFile("8028_TRIM_", ".DER")); //$NON-NLS-1$ //$NON-NLS-2$
		) {
			fos.write(trimmedData);
		}
	}

	/** Prueba de an&aacute;lisis del fichero 2F:FF:80:23.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void test8023() throws Exception {
		final byte[] data = AOUtil.getDataFromInputStream(
			TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/8023_7519421280536555097.DER.txt") //$NON-NLS-1$
		);
		System.out.println(HexUtils.hexify(data, true));
		final byte[] trimmedData = new byte[data.length-5];
		System.arraycopy(data, 5, trimmedData, 0, trimmedData.length);
		System.out.println();
		System.out.println();
		System.out.println(HexUtils.hexify(trimmedData, true));
		try (
			final OutputStream fos = new FileOutputStream(File.createTempFile("8023_TRIM_", ".DER")); //$NON-NLS-1$ //$NON-NLS-2$
		) {
			fos.write(trimmedData);
		}
	}

	/** Prueba de an&aacute;lisis del fichero 2F:FF:80:24.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void test8024() throws Exception {
		final byte[] data = AOUtil.getDataFromInputStream(
			TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/8024_3159855238388326518.DER.txt") //$NON-NLS-1$
		);
		System.out.println(HexUtils.hexify(data, true));
		final byte[] trimmedData = new byte[data.length-5];
		System.arraycopy(data, 5, trimmedData, 0, trimmedData.length);
		System.out.println();
		System.out.println();
		System.out.println(HexUtils.hexify(trimmedData, true));
		try (
			final OutputStream fos = new FileOutputStream(File.createTempFile("8024_TRIM_", ".DER")); //$NON-NLS-1$ //$NON-NLS-2$
		) {
			fos.write(trimmedData);
		}
	}

	private final static class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Contruye una Callback con una contrase&ntilde; preestablecida.
	     * @param password Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        setPassword(password);
	    }
	}

}
