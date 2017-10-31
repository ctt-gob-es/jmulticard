package test.es.gob.jmulticard.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import junit.framework.TestCase;

/** Prueba de creaci&oacute;n de CDF PKCS#15.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class TestCdfCreation extends TestCase {

    private static final java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger(TestCdfCreation.class.getName());

    private static final int BUFFER_SIZE = 4096;

    private static final String[] TEST_FILES = new String[] {
        "CDF_GSD.BER", //$NON-NLS-1$
        "CDF_EEE.BER", //$NON-NLS-1$
        "CDF_GVA.BER", //$NON-NLS-1$
        "CDF_JBM.BER", //$NON-NLS-1$
        "CDF_JMA.BER", //$NON-NLS-1$
        "CDF_TGM.BER", //$NON-NLS-1$
        "CDF_TUI_SAMPLE1.asn1" //$NON-NLS-1$
    };

    private static final byte[] SAMPLE_CDF = new byte[] {
		(byte) 0x30, (byte) 0x81, (byte) 0x84, (byte) 0x30, (byte) 0x0E, (byte) 0x0C, (byte) 0x05, (byte) 0x46,
		(byte) 0x49, (byte) 0x52, (byte) 0x4D, (byte) 0x41, (byte) 0x03, (byte) 0x02, (byte) 0x06, (byte) 0x40,
		(byte) 0x04, (byte) 0x01, (byte) 0x02, (byte) 0x30, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x9B,
		(byte) 0x99, (byte) 0xAF, (byte) 0x11, (byte) 0x22, (byte) 0x81, (byte) 0x57, (byte) 0xCF, (byte) 0xED,
		(byte) 0x7A, (byte) 0x4D, (byte) 0x27, (byte) 0x60, (byte) 0x50, (byte) 0xBE, (byte) 0x9C, (byte) 0x2D,
		(byte) 0xED, (byte) 0x98, (byte) 0x7B, (byte) 0xA1, (byte) 0x5A, (byte) 0x30, (byte) 0x58, (byte) 0x30,
		(byte) 0x0F, (byte) 0x04, (byte) 0x06, (byte) 0x3F, (byte) 0xFF, (byte) 0x43, (byte) 0x02, (byte) 0x16,
		(byte) 0xE6, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x80, (byte) 0x02, (byte) 0x08, (byte) 0x4D,
		(byte) 0xA0, (byte) 0x45, (byte) 0x30, (byte) 0x43, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11,
		(byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0C, (byte) 0x0A, (byte) 0x41,
		(byte) 0x43, (byte) 0x43, (byte) 0x56, (byte) 0x43, (byte) 0x41, (byte) 0x2D, (byte) 0x31, (byte) 0x32,
		(byte) 0x30, (byte) 0x31, (byte) 0x10, (byte) 0x30, (byte) 0x0E, (byte) 0x06, (byte) 0x03, (byte) 0x55,
		(byte) 0x04, (byte) 0x0B, (byte) 0x0C, (byte) 0x07, (byte) 0x50, (byte) 0x4B, (byte) 0x49, (byte) 0x41,
		(byte) 0x43, (byte) 0x43, (byte) 0x56, (byte) 0x31, (byte) 0x0D, (byte) 0x30, (byte) 0x0B, (byte) 0x06,
		(byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0A, (byte) 0x0C, (byte) 0x04, (byte) 0x41, (byte) 0x43,
		(byte) 0x43, (byte) 0x56, (byte) 0x31, (byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03,
		(byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x45, (byte) 0x53, (byte) 0x30,
		(byte) 0x81, (byte) 0x8A, (byte) 0x30, (byte) 0x10, (byte) 0x0C, (byte) 0x07, (byte) 0x43, (byte) 0x49,
		(byte) 0x46, (byte) 0x52, (byte) 0x41, (byte) 0x44, (byte) 0x4F, (byte) 0x03, (byte) 0x02, (byte) 0x06,
		(byte) 0x40, (byte) 0x04, (byte) 0x01, (byte) 0x02, (byte) 0x30, (byte) 0x1A, (byte) 0x04, (byte) 0x18,
		(byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x2F, (byte) 0xD8, (byte) 0x79, (byte) 0xDF,
		(byte) 0x9E, (byte) 0xAC, (byte) 0x07, (byte) 0xB1, (byte) 0x00, (byte) 0x04, (byte) 0x0F, (byte) 0xF6,
		(byte) 0x6C, (byte) 0xD2, (byte) 0x27, (byte) 0x1E, (byte) 0xA6, (byte) 0x21, (byte) 0x68, (byte) 0x3A,
		(byte) 0xA1, (byte) 0x5A, (byte) 0x30, (byte) 0x58, (byte) 0x30, (byte) 0x0F, (byte) 0x04, (byte) 0x06,
		(byte) 0x3F, (byte) 0xFF, (byte) 0x43, (byte) 0x02, (byte) 0x2C, (byte) 0x23, (byte) 0x02, (byte) 0x01,
		(byte) 0x00, (byte) 0x80, (byte) 0x02, (byte) 0x08, (byte) 0x4D, (byte) 0xA0, (byte) 0x45, (byte) 0x30,
		(byte) 0x43, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55,
		(byte) 0x04, (byte) 0x03, (byte) 0x0C, (byte) 0x0A, (byte) 0x41, (byte) 0x43, (byte) 0x43, (byte) 0x56,
		(byte) 0x43, (byte) 0x41, (byte) 0x2D, (byte) 0x31, (byte) 0x32, (byte) 0x30, (byte) 0x31, (byte) 0x10,
		(byte) 0x30, (byte) 0x0E, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0B, (byte) 0x0C,
		(byte) 0x07, (byte) 0x50, (byte) 0x4B, (byte) 0x49, (byte) 0x41, (byte) 0x43, (byte) 0x43, (byte) 0x56,
		(byte) 0x31, (byte) 0x0D, (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
		(byte) 0x0A, (byte) 0x0C, (byte) 0x04, (byte) 0x41, (byte) 0x43, (byte) 0x43, (byte) 0x56, (byte) 0x31,
		(byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06,
		(byte) 0x13, (byte) 0x02, (byte) 0x45, (byte) 0x53
    };

    /** Prueba de CDF de ejemplo (extra&iacute;do de una tarjeta GyD de ACCV).
     * @throws Exception En cualquier error. */
    @Test
    public static void testSampleCdf() throws Exception {
        final Cdf cdf = new Cdf();
        Assert.assertNotNull(cdf);
        cdf.setDerValue(SAMPLE_CDF);
        LOGGER.info("\n" + cdf.toString()); //$NON-NLS-1$
    }

    /** Prueba la creaci&oacute;n de CDF con volcados en disco.
     * @throws Exception En caso de cualquier tipo de error */
    @Test
    public static void testCdf() throws Exception {
        byte[] cdfdata;
        for (final String element : TEST_FILES) {
            cdfdata = getDataFromInputStream(ClassLoader.getSystemResourceAsStream(element));
            LOGGER.info("\n\nCDF completo (" + Integer.toString(cdfdata.length) + "):"); //$NON-NLS-1$ //$NON-NLS-2$
            LOGGER.info(HexUtils.hexify(cdfdata, true));
            final Cdf cdf = new Cdf();
            Assert.assertNotNull(cdf);
            cdf.setDerValue(cdfdata);
            LOGGER.info("\n" + cdf.toString()); //$NON-NLS-1$
        }
    }

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