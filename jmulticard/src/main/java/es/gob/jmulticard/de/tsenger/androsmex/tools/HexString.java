package es.gob.jmulticard.de.tsenger.androsmex.tools;

/** Funciones de manipulaci&oacute;n de tipos Hexadecimal y String.
 * @author Sergio Mart&iacute;nez Rico */
public class HexString {

	/** Convierte de String a Hexadecimal.
	 * @param s Cadena a convertir.
	 * @return Cadena convertida a hexadecimal.
	 */
	public static String stringToHex(final String s)
	{
		final byte[] stringBytes = s.getBytes();
		return HexString.bufferToHex(stringBytes);
	}

	/** Convierte de Buffer a Hexadecimal.
	 * @param buffer Buffer a convertir.
	 * @return Buffer convertido a hexadecimal.
	 */
	public static String bufferToHex(final byte buffer[])
	{
		return HexString.bufferToHex(buffer, 0, buffer.length);
	}

	/** Convierte de Buffer a Hexadecimal.
	 * @param buffer Buffer a convertir.
	 * @param startOffset Comienzo de lectura en la conversi&oacute;n.
	 * @param length Longitud de lectura en la conversi&oacute;n.
	 * @return Buffer convertido a hexadecimal.
	 */
	public static String bufferToHex(final byte buffer[], final int startOffset, final int length)
	{
		final StringBuffer hexString = new StringBuffer(2 * length);
		final int endOffset = startOffset + length;
		for (int i = startOffset; i < endOffset; i++) {
			HexString.appendHexPair(buffer[i], hexString);
			hexString.append(" "); //$NON-NLS-1$
			if ((i+1)%16 == 0)
			 {
				hexString.append("\n"); //$NON-NLS-1$
			}
		}
		return hexString.toString();
	}

	/** Convierte de Hexadecimal a String.
	 * @param hexString Hexadecimal a convertir.
	 * @return Hexadecimal convertido a cadena.
	 * @throws NumberFormatException Lanza la excepci&oacute;n en caso de que el Hexadecimal
	 * 								 no tenga un formato correcto.
	 */
	public static String hexToString(final String hexString)
			throws NumberFormatException
	{
		final byte[] bytes = HexString.hexToBuffer(hexString);
		return new String(bytes);
	}

	/** Convierte de Hexadecimal a Buffer.
	 * @param hexString Hexadecimal a convertir.
	 * @return Hexadecimal convertido a Buffer.
	 * @throws NumberFormatException Lanza la excepci&oacute;n en caso de que el Hexadecimal
	 * 								 no tenga un formato correcto.
	 */
	public static byte[] hexToBuffer(final String hexString)
			throws NumberFormatException
	{
		final int length = hexString.length();
		final byte[] buffer = new byte[(length + 1) / 2];
		boolean evenByte = true;
		byte nextByte = 0;
		int bufferOffset = 0;
		if (length % 2 == 1) {
			evenByte = false;
		}
		for (int i = 0; i < length; i++) {
			final char c = hexString.charAt(i);
			int nibble;
			if (c >= '0' && c <= '9') {
				nibble = c - '0';
			} else if (c >= 'A' && c <= 'F') {
				nibble = c - 'A' + 0x0A;
			} else if (c >= 'a' && c <= 'f') {
				nibble = c - 'a' + 0x0A;
			}
			else {
				throw new NumberFormatException("Invalid hex digit '" + c + "'."); //$NON-NLS-1$ //$NON-NLS-2$
			}
			if (evenByte) {
				nextByte = (byte) (nibble << 4);
			} else {
				nextByte += (byte) nibble;
				buffer[bufferOffset++] = nextByte;
			}
			evenByte = !evenByte;
		}
		return buffer;
	}

	private static void appendHexPair(final byte b, final StringBuffer hexString)
	{
		final char highNibble = kHexChars[(b & 0xF0) >> 4];
		final char lowNibble = kHexChars[b & 0x0F];
		hexString.append(highNibble);
		hexString.append(lowNibble);
	}
	private static final char kHexChars[] = { '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
}