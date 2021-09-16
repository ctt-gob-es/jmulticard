package es.gob.jmulticard.jsr268;

import java.util.Arrays;

import es.gob.jmulticard.card.gemalto.tuir5.TuiR5;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de Gemalto TUI R5.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestTui {

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final TuiR5 tui = new TuiR5(
			new SmartcardIoConnection(),
			new CachePasswordCallback("1111".toCharArray()) //$NON-NLS-1$
		);
		System.out.println(tui.getCardName());
		System.out.println(Arrays.asList(tui.getAliases()));
		System.out.println(tui.getPrivateKey(tui.getAliases()[0]));
	}

}
