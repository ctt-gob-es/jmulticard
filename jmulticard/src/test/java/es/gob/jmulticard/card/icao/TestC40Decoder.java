package es.gob.jmulticard.card.icao;

import java.io.IOException;

import org.junit.Test;

/** Pruebas de decodificaci&oacute;n de texo en formato C40 (ISO 16022).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestC40Decoder {

	private static final byte[] TEST_C40_1 = {
			(byte) 0xdd, (byte) 0x52, (byte) 0x13, (byte) 0x4a, (byte) 0x74, (byte) 0xda, (byte) 0x13, (byte) 0x47,
			(byte) 0xc6, (byte) 0xfe, (byte) 0xd9, (byte) 0x5c, (byte) 0xb8, (byte) 0x9f, (byte) 0x9f, (byte) 0xce,
			(byte) 0x13, (byte) 0x3c, (byte) 0x13, (byte) 0x3c, (byte) 0x13, (byte) 0x3c, (byte) 0x13, (byte) 0x3c,
			(byte) 0x20, (byte) 0x38, (byte) 0x33, (byte) 0x73, (byte) 0x4a, (byte) 0xaf, (byte) 0x47, (byte) 0xf0,
			(byte) 0xc3, (byte) 0x2f, (byte) 0x1a, (byte) 0x1e, (byte) 0x20, (byte) 0xeb, (byte) 0x26, (byte) 0x25,
			(byte) 0x39, (byte) 0x3a, (byte) 0xfe, (byte) 0x31
		};

		private static final byte[] TEST_C40_2 = {
			(byte) 0x59, (byte) 0xe9, (byte) 0x32, (byte) 0xf9, (byte) 0x26, (byte) 0xc7
		};

		private static final byte[] TEST_C40_3 = {
			(byte) 0x31, (byte) 0x9f, (byte) 0x27
		};

		/** Prueba de decodificaci&oacute;n de texo en formato C40 (ISO 16022).
		 * @throws IOException En cualquier error. */
		@Test
		@SuppressWarnings("static-method")
		public void testDecode() throws IOException {
			String test = C40Decoder.decode(TEST_C40_1);
			System.out.println("Binario: " + TEST_C40_1.length + " bytes (" + TEST_C40_1.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);

			test = C40Decoder.decode(TEST_C40_2);
			System.out.println("Binario: " + TEST_C40_2.length + " bytes (" + TEST_C40_2.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);

			test = C40Decoder.decode(TEST_C40_3);
			System.out.println("Binario: " + TEST_C40_3.length + " bytes (" + TEST_C40_3.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);
		}

}
