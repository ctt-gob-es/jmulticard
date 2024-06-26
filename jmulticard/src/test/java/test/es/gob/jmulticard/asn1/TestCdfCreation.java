package test.es.gob.jmulticard.asn1;

import java.io.InputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;

/** Prueba de creaci&oacute;n de CDF PKCS#15.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestCdfCreation {

    private static final String[] CDF_TEST_FILES = {
        "CDF_GSD.BER", //$NON-NLS-1$
        "CDF_EEE.BER", //$NON-NLS-1$
        "CDF_GVA.BER", //$NON-NLS-1$
        "CDF_JBM.BER", //$NON-NLS-1$
        "CDF_JMA.BER", //$NON-NLS-1$
        "CDF_TGM.BER", //$NON-NLS-1$
        "CDF_TUI_SAMPLE1.asn1" //$NON-NLS-1$
    };

    private static final byte[] SAMPLE_CDF = {
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
    @SuppressWarnings("static-method")
	@Test
    void testSampleCdf() throws Exception {
        final Cdf cdf = new Cdf();
        Assertions.assertNotNull(cdf);
        cdf.setDerValue(SAMPLE_CDF);
        System.out.println("\n" + cdf.toString()); //$NON-NLS-1$
    }

    /** Prueba la creaci&oacute;n de CDF con volcados en disco.
     * @throws Exception En caso de cualquier tipo de error */
    @SuppressWarnings("static-method")
	@Test
    void testCdf() throws Exception {
        byte[] cdfdata;
        for (final String element : CDF_TEST_FILES) {
        	try (InputStream is = ClassLoader.getSystemResourceAsStream(element)) {
        		cdfdata = TestingUtil.getDataFromInputStream(is);
        	}
        	System.out.println("\n\nCDF completo (" + Integer.toString(cdfdata.length) + "):"); //$NON-NLS-1$ //$NON-NLS-2$
        	System.out.println(HexUtils.hexify(cdfdata, true));
            final Cdf cdf = new Cdf();
            Assertions.assertNotNull(cdf);
            cdf.setDerValue(cdfdata);
            System.out.println("\n" + cdf.toString()); //$NON-NLS-1$
        }
    }
}