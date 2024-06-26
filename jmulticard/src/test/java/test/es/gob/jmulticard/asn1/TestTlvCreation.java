package test.es.gob.jmulticard.asn1;

import java.io.InputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Tlv;

/** Prueba de creaci&oacute;n de TLV.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestTlvCreation {

    private static final String[] TEST_FILES = {
        "CDF_EEE.BER", //$NON-NLS-1$
        "CDF_GSD.BER", //$NON-NLS-1$
        "CDF_GVA.BER", //$NON-NLS-1$
        "CDF_JBM.BER", //$NON-NLS-1$
        "CDF_JMA.BER", //$NON-NLS-1$
        "CDF_TGM.BER" //$NON-NLS-1$
    };

    /** Prueba la creaci&oacute;n de TLV con volcados de CDF.
     * @throws Exception en caso de cualquier tipo de error */
	@SuppressWarnings("static-method")
	@Test
	void testTlv() throws Exception {
        byte[] cdfdata;
        for (final String element : TEST_FILES) {
        	try (final InputStream is = ClassLoader.getSystemResourceAsStream(element)) {
        		cdfdata = TestingUtil.getDataFromInputStream(is);
        	}

            final Tlv tlv = new Tlv(cdfdata);
            Assertions.assertNotNull(tlv);
            System.out.println(tlv.toString());
            System.out.println("\n\nProbando " + element); //$NON-NLS-1$
            System.out.println("\nTLV completo (" + Integer.toString(tlv.getBytes().length) + "):"); //$NON-NLS-1$ //$NON-NLS-2$
            System.out.println(HexUtils.hexify(tlv.getBytes(), true));
            System.out.println("\nTipo TLV:"); //$NON-NLS-1$
            System.out.println(
        		HexUtils.hexify(
    				new byte[] { tlv.getTag() },
    				true
				)
    		);
            System.out.println("\nLongitud TLV:"); //$NON-NLS-1$
            System.out.println(Integer.toString(tlv.getLength()));
            System.out.println("\nValor TLV (" + Integer.toString(tlv.getValue().length) + "):"); //$NON-NLS-1$ //$NON-NLS-2$
            System.out.println(HexUtils.hexify(tlv.getValue(), true));
        }
    }
}