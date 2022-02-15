package test.es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;

/** Utilidad de generaci&oacute;n de claves a partir de constantes.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestKeyGeneration {

    /** C&oacute;digo auxiliar para el c&aacute;lculo de la clave Kenc del canal seguro. */
    private static final byte[] SECURE_CHANNEL_KENC_AUX = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    /** C&oacute;digo auxiliar para el c&aacute;lculo de la clave Kmac del canal seguro. */
    private static final byte[] SECURE_CHANNEL_KMAC_AUX = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02
    };

	private static final CryptoHelper CRYPTO_HELPER = new JseCryptoHelper();

	private static final byte[] K_IDF = {
		(byte) 0xD8, (byte) 0xE2, (byte) 0x5F, (byte) 0x21, (byte) 0x3F, (byte) 0x58, (byte) 0xA3, (byte) 0x1F,
		(byte) 0x38, (byte) 0x31, (byte) 0x6A, (byte) 0xA9, (byte) 0x22, (byte) 0xC4, (byte) 0x8A, (byte) 0x93,
		(byte) 0xBA, (byte) 0xA9, (byte) 0x3C, (byte) 0x8B, (byte) 0x1F, (byte) 0x7A, (byte) 0x18, (byte) 0x51,
		(byte) 0xD0, (byte) 0xEB, (byte) 0x74, (byte) 0x60, (byte) 0x59, (byte) 0xB6, (byte) 0x13, (byte) 0xFD
	};

	private static final byte[] K_ICC = {
		(byte) 0x5A, (byte) 0xEF, (byte) 0x06, (byte) 0x2A, (byte) 0xFD, (byte) 0x9F, (byte) 0x0D, (byte) 0xBA,
		(byte) 0xC9, (byte) 0x11, (byte) 0x3A, (byte) 0x9E, (byte) 0x6D, (byte) 0x7A, (byte) 0xB2, (byte) 0x88,
		(byte) 0xCC, (byte) 0x4E, (byte) 0x45, (byte) 0x5D, (byte) 0xAA, (byte) 0x09, (byte) 0x8D, (byte) 0xB8,
		(byte) 0xD1, (byte) 0x8C, (byte) 0x82, (byte) 0x37, (byte) 0xE7, (byte) 0x72, (byte) 0x67, (byte) 0x88
	};

    /** Genera la clave KENC para encriptar y desencriptar criptogramas.
     * @param kidficc XOR de los valores Kifd y Kicc.
     * @return Clave AES.
     * @throws IOException Cuando no puede generarse la clave. */
    private static byte[] generateKenc(final byte[] kidficc) throws IOException {
        // La clave de cifrado Kenc se obtiene como los 16 primeros bytes del hash de la
        // concatenacion de kifdicc con el valor "00 00 00 01" (SECURE_CHANNEL_KENC_AUX).
    	final byte[] kidficcConcat = HexUtils.concatenateByteArrays(kidficc, SECURE_CHANNEL_KENC_AUX);

    	System.out.println("Datos para el hash de Kenc: " + HexUtils.hexify(kidficcConcat, false)); //$NON-NLS-1$

        final byte[] keyEnc = new byte[16];
        System.arraycopy(
    		TestKeyGeneration.CRYPTO_HELPER.digest(
				CryptoHelper.DigestAlgorithm.SHA256,
				kidficcConcat
			),
			0,
			keyEnc,
			0,
			keyEnc.length
		);

        return keyEnc;
    }

    /** Genera la clave KMAC para calcular y verificar checksums.
     * @param kidficc XOR de los valores Kifd y Kicc.
     * @return Clave AES.
     * @throws IOException Cuando no puede generarse la clave. */
    private static byte[] generateKmac(final byte[] kidficc) throws IOException {
        // La clave para el calculo del MAC Kmac se obtiene como los 16 primeros bytes
        // del hash de la concatenacion de kifdicc con el valor "00 00 00 02" (SECURE_CHANNEL_KMAC_AUX).
        final byte[] kidficcConcat = HexUtils.concatenateByteArrays(kidficc, SECURE_CHANNEL_KMAC_AUX);

        final byte[] keyMac = new byte[16];
        System.arraycopy(
    		TestKeyGeneration.CRYPTO_HELPER.digest(
				CryptoHelper.DigestAlgorithm.SHA256,
				kidficcConcat
			),
    		0,
    		keyMac,
    		0,
    		keyMac.length
		);

        return keyMac;
    }

    /** Prueba de generaci&oacute;n de claves de canal.
     * @throws Exception en cualquier error. */
    @SuppressWarnings("static-method")
	@Test
    public void testKeysGeneration() throws Exception {

        // Calculamos Kifdicc como el XOR de los valores Kifd y Kicc
        final byte[] kidficc = HexUtils.xor(K_ICC, K_IDF);
        Assert.assertEquals(
    		"820d590bc2c7aea5f12050374fbe381b76e779d6b57395e90167f657bec47475", //$NON-NLS-1$
        	HexUtils.hexify(kidficc, false).toLowerCase()
    	);

        final byte[] kenc = generateKenc(kidficc);
        System.out.println("Kenc: " + HexUtils.hexify(kenc, false)); //$NON-NLS-1$

        final byte[] kmac = generateKmac(kidficc);
        System.out.println("Kmac: " + HexUtils.hexify(kmac, false)); //$NON-NLS-1$

    }

}
