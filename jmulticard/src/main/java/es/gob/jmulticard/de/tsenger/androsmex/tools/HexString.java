package es.gob.jmulticard.de.tsenger.androsmex.tools;

public class HexString {

	public static String stringToHex(String s)
	{
		byte[] stringBytes = s.getBytes();
		return HexString.bufferToHex(stringBytes);
	}

	public static String bufferToHex(byte buffer[])
	{
		return HexString.bufferToHex(buffer, 0, buffer.length);
	}

	public static String bufferToHex(byte buffer[], int startOffset, int length)
	{
		StringBuffer hexString = new StringBuffer(2 * length);
		int endOffset = startOffset + length;
		for (int i = startOffset; i < endOffset; i++) {
			HexString.appendHexPair(buffer[i], hexString);
			hexString.append(" "); //$NON-NLS-1$
			if ((i+1)%16 == 0) hexString.append("\n"); //$NON-NLS-1$
		}
		return hexString.toString();
	}

	public static String hexToString(String hexString)
			throws NumberFormatException
	{
		byte[] bytes = HexString.hexToBuffer(hexString);
		return new String(bytes);
	}

	public static byte[] hexToBuffer(String hexString)
			throws NumberFormatException
	{
		int length = hexString.length();
		byte[] buffer = new byte[(length + 1) / 2];
		boolean evenByte = true;
		byte nextByte = 0;
		int bufferOffset = 0;
		if ((length % 2) == 1)
			evenByte = false;
		for (int i = 0; i < length; i++) {
			char c = hexString.charAt(i);
			int nibble;
			if ((c >= '0') && (c <= '9'))
				nibble = c - '0';
			else if ((c >= 'A') && (c <= 'F'))
				nibble = c - 'A' + 0x0A;
			else if ((c >= 'a') && (c <= 'f'))
				nibble = c - 'a' + 0x0A;
			else
				throw new NumberFormatException("Invalid hex digit '" + c + "'."); //$NON-NLS-1$ //$NON-NLS-2$
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

	private static void appendHexPair(byte b, StringBuffer hexString)
	{
		char highNibble = kHexChars[(b & 0xF0) >> 4];
		char lowNibble = kHexChars[b & 0x0F];
		hexString.append(highNibble);
		hexString.append(lowNibble);
	}
	private static final char kHexChars[] = { '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
}