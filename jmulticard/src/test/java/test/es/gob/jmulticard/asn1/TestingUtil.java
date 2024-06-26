package test.es.gob.jmulticard.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Utilidades comunes para las pruebas.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestingUtil {

    private static final int BUFFER_SIZE = 4096;

	private TestingUtil() {
		// No instanciable
	}

    /** Lee un flujo de datos de entrada y los recupera en forma de array de
     * bytes. Se consume, pero no se cierra el flujo de datos de entrada.
     * @param input Flujo de donde se toman los datos.
     * @return Los datos obtenidos del flujo.
     * @throws IOException Cuando ocurre un problema durante la lectura */
    static byte[] getDataFromInputStream(final InputStream input) throws IOException {
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
