package es.gob.jmulticard;

import java.util.Arrays;

import es.gob.jmulticard.card.cardos.CardOS;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de Gemalto TUI R5.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestCardOS {

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final CardOS cardos = new CardOS(
			new SmartcardIoConnection()
		);
		System.out.println(cardos.getCardName());
		System.out.println(Arrays.asList(cardos.getAliases()));
		//System.out.println(tui.getPrivateKey(tui.getAliases()[0]));
	}

}
