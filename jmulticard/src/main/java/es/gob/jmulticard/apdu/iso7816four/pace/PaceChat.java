package es.gob.jmulticard.apdu.iso7816four.pace;

import es.gob.jmulticard.HexUtils;

/** PACE CHAT para la selecci&oacute;n de algoritmo para PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceChat {

	private static final byte[] TAG = { (byte)0x7f, (byte)0x4c };

	/** Tipo de terminal en el contexto de un PACE CHAT para la selecci&oacute;n de algoritmo para PACE. */
	public enum TerminalType {

		/** Signature Terminal {id-roles 3}, Discretionary Data: Privileg. */
		ST(new byte[] {
			(byte)0x06, // Tipo OID
			(byte)0x09, // Len = 9
			(byte)0x04, (byte)0x00, (byte)0x7f, (byte)0x00, (byte)0x07, (byte)0x03, (byte)0x01, (byte)0x02, (byte)0x03, // OID = ST terminal {id-roles 3}

			(byte)0x53, // Tipo Discretionary Data
			(byte)0x01, // Len = 1
			(byte)0x02  // Discretionary Data = Privileg (autorizacion efectiva)
		});

		private final byte[] encoding;

		TerminalType(final byte[] body) {
			encoding = body;
		}

		byte[] getBytes() {
			return encoding;
		}
	}

	private final TerminalType terminalType;

	/** Construye un PACE CHAT para la selecci&oacute;n de algoritmo para PACE.
	 * @param termType Tipo de terminal. */
	public PaceChat(final TerminalType termType) {
		terminalType = termType;
	}

	byte[] getBytes() {
		final byte[] terminalTypeBytes = terminalType.getBytes();
		return HexUtils.concatenateByteArrays(TAG, new byte[] { (byte) terminalTypeBytes.length }, terminalTypeBytes);
	}
}
