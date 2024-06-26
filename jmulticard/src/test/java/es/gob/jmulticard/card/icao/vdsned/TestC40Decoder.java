package es.gob.jmulticard.card.icao.vdsned;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Pruebas de decodificaci&oacute;n de texo en formato C40 (ISO 16022).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestC40Decoder {

	private static final byte[] JAPAN = {
		(byte) 0x5b, (byte) 0xe2, (byte) 0xf2, (byte) 0xae, (byte) 0x43, (byte) 0x60, (byte) 0x77, (byte) 0xe8,
		(byte) 0xc0, (byte) 0x51, (byte) 0x1d, (byte) 0x23, (byte) 0x58, (byte) 0x60, (byte) 0x43, (byte) 0xe7,
		(byte) 0x8d, (byte) 0xfd, (byte) 0xc0, (byte) 0xae, (byte) 0x69, (byte) 0x84, (byte) 0x71, (byte) 0x7c,
		(byte) 0xe5, (byte) 0x1a, (byte) 0xc2, (byte) 0x44, (byte) 0x4c, (byte) 0x70, (byte) 0x10, (byte) 0x68,
		(byte) 0xaf, (byte) 0x84, (byte) 0xb4, (byte) 0x07, (byte) 0x32, (byte) 0xf2, (byte) 0xec, (byte) 0x1d,
		(byte) 0xab, (byte) 0x1c, (byte) 0xe4, (byte) 0xe2, (byte) 0x46, (byte) 0xed, (byte) 0xc3, (byte) 0x16,
		(byte) 0xca, (byte) 0xb7, (byte) 0x95, (byte) 0x38, (byte) 0x8c, (byte) 0x39, (byte) 0xeb, (byte) 0xe4,
		(byte) 0x08, (byte) 0xa0, (byte) 0xbb, (byte) 0x2d, (byte) 0x9e, (byte) 0xab, (byte) 0x57, (byte) 0x7a,
		(byte) 0x48, (byte) 0x72, (byte) 0x41, (byte) 0x4c, (byte) 0xdf, (byte) 0x39, (byte) 0x3b, (byte) 0x8d,
		(byte) 0x1f, (byte) 0xc4, (byte) 0xc2, (byte) 0xa7, (byte) 0x22, (byte) 0x85, (byte) 0x48, (byte) 0x1d,
		(byte) 0x0d, (byte) 0xe5, (byte) 0x94, (byte) 0x99, (byte) 0x92, (byte) 0x4c, (byte) 0x8e, (byte) 0xb6,
		(byte) 0x45, (byte) 0x09, (byte) 0x43, (byte) 0x1f, (byte) 0x7e, (byte) 0xbd, (byte) 0x75, (byte) 0x6e,
		(byte) 0xa9, (byte) 0x7f, (byte) 0x4d, (byte) 0x33, (byte) 0x0a, (byte) 0x67, (byte) 0x46, (byte) 0x22,
		(byte) 0x3c, (byte) 0xc4, (byte) 0xc4, (byte) 0x2e, (byte) 0x74, (byte) 0x80, (byte) 0x94, (byte) 0x88,
		(byte) 0x6b, (byte) 0x53, (byte) 0xbb, (byte) 0x68, (byte) 0xdb, (byte) 0x39, (byte) 0x4b, (byte) 0x20,
		(byte) 0x7a, (byte) 0xb9, (byte) 0x24, (byte) 0xc6, (byte) 0xb1, (byte) 0xb1, (byte) 0x95, (byte) 0xcb,
		(byte) 0x43, (byte) 0x45, (byte) 0x05, (byte) 0xb7, (byte) 0x58, (byte) 0x18, (byte) 0x04, (byte) 0x7e,
		(byte) 0xbb, (byte) 0x2d, (byte) 0x43, (byte) 0x2d, (byte) 0x98, (byte) 0x9d, (byte) 0x6f, (byte) 0x7f,
		(byte) 0xd8, (byte) 0x0d, (byte) 0x20, (byte) 0x6d, (byte) 0x9b, (byte) 0x9d, (byte) 0x8b, (byte) 0x5c,
		(byte) 0x86, (byte) 0x91, (byte) 0x1a, (byte) 0x4c, (byte) 0x24, (byte) 0x50, (byte) 0x4e, (byte) 0xc5,
		(byte) 0x34, (byte) 0xf7, (byte) 0xf4, (byte) 0x1e, (byte) 0x56, (byte) 0xc9, (byte) 0xd9, (byte) 0x83,
		(byte) 0x5b, (byte) 0x63, (byte) 0x9d, (byte) 0x1c, (byte) 0x32, (byte) 0x27, (byte) 0x0a, (byte) 0xb2,
		(byte) 0xd5, (byte) 0xa0, (byte) 0xcc, (byte) 0x0e, (byte) 0x6f, (byte) 0x9a, (byte) 0xc5, (byte) 0x30,
		(byte) 0x10, (byte) 0x67, (byte) 0xed, (byte) 0xd9, (byte) 0x48, (byte) 0x5e, (byte) 0xe6, (byte) 0xb4,
		(byte) 0x00, (byte) 0x1e, (byte) 0x5a, (byte) 0x79, (byte) 0xcc, (byte) 0x4d, (byte) 0x6f, (byte) 0x1c,
		(byte) 0x5f, (byte) 0xe7, (byte) 0x32, (byte) 0xbd, (byte) 0x7e, (byte) 0x00, (byte) 0xca, (byte) 0x68,
		(byte) 0x3c, (byte) 0x68, (byte) 0x4d, (byte) 0xc9, (byte) 0x0d, (byte) 0x65, (byte) 0xd0, (byte) 0x77,
		(byte) 0x26, (byte) 0x9a, (byte) 0x0a, (byte) 0x62, (byte) 0x18, (byte) 0xbc, (byte) 0x56, (byte) 0x07,
		(byte) 0x7e, (byte) 0xda, (byte) 0x85, (byte) 0xe8, (byte) 0xf7, (byte) 0xd8, (byte) 0xde, (byte) 0x48,
		(byte) 0x85, (byte) 0x87, (byte) 0xb7, (byte) 0x88, (byte) 0x3f, (byte) 0x86, (byte) 0x81, (byte) 0xcb,
		(byte) 0x57, (byte) 0x5a, (byte) 0xe8, (byte) 0x91, (byte) 0x65, (byte) 0xce, (byte) 0x2c, (byte) 0x92
	};

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

	private static final byte[] TEST_C40_4 = {
		(byte) 0xd9, (byte) 0xad, (byte) 0x22, (byte) 0x4c, (byte) 0x5a, (byte) 0x8c
	};

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws IOException En cualquier error. */
	public static void main(final String[] args) throws IOException {
		System.out.println(new String(JAPAN, StandardCharsets.UTF_8));
		System.out.println();
		System.out.println();
		System.out.println();
//		System.out.println(C40Decoder.decode(JAPAN));
	}

	/** Prueba de decodificaci&oacute;n de texo en formato C40 (ISO 16022). */
	@Test
	@SuppressWarnings("static-method")
	void testDecode() {
		try {
			String test = C40Decoder.decode(TEST_C40_1);
			System.out.println("Binario: " + TEST_C40_1.length + " bytes (" + TEST_C40_1.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);

			System.out.println();

			test = C40Decoder.decode(TEST_C40_2);
			System.out.println("Binario: " + TEST_C40_2.length + " bytes (" + TEST_C40_2.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);

			System.out.println();

			test = C40Decoder.decode(TEST_C40_3);
			System.out.println("Binario: " + TEST_C40_3.length + " bytes (" + TEST_C40_3.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);

			System.out.println();

	//		test = C40Decoder.decode(JAPAN);
	//		System.out.println("Binario: " + JAPAN.length + " bytes (" + JAPAN.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	//		System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
	//		System.out.println(test);
	//
	//		System.out.println();

			test = C40Decoder.decode(TEST_C40_4);
			System.out.println("Binario: " + TEST_C40_4.length + " bytes (" + TEST_C40_4.length/2*3 + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			System.out.println("Caracteres: " + test.length()); //$NON-NLS-1$
			System.out.println(test);
		}
		catch(final IOException e) {
			e.printStackTrace();
			Assertions.fail();
		}
	}
}
