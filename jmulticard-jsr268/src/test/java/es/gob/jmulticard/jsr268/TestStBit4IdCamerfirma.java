package es.gob.jmulticard.jsr268;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
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
		final byte[] data;
		try (
			final InputStream is = TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/0000_7076199932780544215.DER.txt") //$NON-NLS-1$
		) {
			data = getDataFromInputStream(
				is
			);
		}
		System.out.println(HexUtils.hexify(data, true));
	}

	/** Prueba de an&aacute;lisis del fichero 2F:FF:80:28.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void test8028() throws Exception {
		final byte[] data;
		try (
			final InputStream is = TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/8028_6486727951599148607.DER.txt") //$NON-NLS-1$
		) {
			data = getDataFromInputStream(
				is
			);
		}
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
		final byte[] data;
		try (
			final InputStream is = TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/8023_7519421280536555097.DER.txt") //$NON-NLS-1$
		) {
			data = getDataFromInputStream(
				is
			);
		}
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
		final byte[] data;
		try (
			final InputStream is = TestStBit4IdCamerfirma.class.getResourceAsStream("/bit4id-stcm/8024_3159855238388326518.DER.txt") //$NON-NLS-1$
		) {
			data = getDataFromInputStream(
				is
			);
		}
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

    private static final int BUFFER_SIZE = 4096;

    /** Lee un flujo de datos de entrada y los recupera en forma de array de
     * bytes. Este m&eacute;todo consume pero no cierra el flujo de datos de
     * entrada.
     * @param input
     *        Flujo de donde se toman los datos.
     * @return Los datos obtenidos del flujo.
     * @throws IOException
     *         Cuando ocurre un problema durante la lectura */
    private static byte[] getDataFromInputStream(final InputStream input) throws IOException {
        if (input == null) {
            return new byte[0];
        }
        int nBytes = 0;
        final byte[] buffer = new byte[BUFFER_SIZE];
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((nBytes = input.read(buffer)) != -1) {
            baos.write(buffer, 0, nBytes);
        }
        return baos.toByteArray();
    }


}
