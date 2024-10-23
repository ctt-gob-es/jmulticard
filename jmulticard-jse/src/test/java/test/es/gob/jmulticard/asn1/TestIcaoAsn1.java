package test.es.gob.jmulticard.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.crypto.BcCryptoHelper;

/** Pruebas de estructuras ICAO.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestIcaoAsn1 {

    private static final int BUFFER_SIZE = 4096;

    /** Lee un flujo de datos de entrada y los recupera en forma de array de
     * bytes. Este m&eacute;todo consume pero no cierra el flujo de datos de
     * entrada.
     * @param input Flujo de donde se toman los datos.
     * @return Los datos obtenidos del flujo.
     * @throws IOException Cuando ocurre un problema durante la lectura */
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

    /** Main para pruebas.
     * @param args No se usa.
     * @throws Exception En cualquier error. */
    public static void main(final String[] args) throws Exception {
		new TestIcaoAsn1().testSod();
	}

    /** Prueba de an&aacute;lisis del SOD.
     * @throws Exception En cualquier error. */
    @SuppressWarnings("static-method")
	@Test
	void testSod() throws Exception {
    	final byte[] sod1;
    	try (final InputStream is = TestIcaoAsn1.class.getResourceAsStream("/SOD_ESPECIMEN.der")) { //$NON-NLS-1$
    		sod1 = getDataFromInputStream(is);
    	}
    	final Sod sod = new Sod(new BcCryptoHelper());
    	Assertions.assertNotNull(sod);
		sod.setDerValue(sod1);
		System.out.println(sod);
	}
}
