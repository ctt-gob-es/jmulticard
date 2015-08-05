package es.gob.jmulticard;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.pace.PaceChannelHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** pruebas de PACE con DNIe 3.0.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestPaceDnie {

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final ApduConnection conn = new SmartcardIoConnection();
//		System.out.println(conn.getTerminalInfo((int) conn.getTerminals(true)[0]));
//		conn.setTerminal((int) conn.getTerminals(true)[0]);
		PaceChannelHelper.openPaceChannel((byte)0x10, conn);
	}

}
