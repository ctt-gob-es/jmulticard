package es.inteco.labs.android.usb.device.ccid.instruction;

/** Utilidades.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class InstructionUtil {

	private InstructionUtil() {
		// Vacio
	}

    /** Convierte un entero a un <i>array</i> de octetos de 4 posiciones,
     * ordenado de izquierda a derecha.
     * @param value Entero a convertir.
     * @return <i>Array</i> de octetos resultante. */
    static byte[] intToByteArray(final int value) {
        final byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[3 - i] = (byte) (value >>> offset & 0xFF);
        }
        return b;
    }
}
