package es.gob.jmulticard;

import java.util.Arrays;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.card.gemalto.tuir5.TuiR5;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de Gemalto TUI R5.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestTui {


	final static class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Contruye una Callback con una contrase&ntilde; preestablecida.
	     * @param password Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        this.setPassword(password);
	    }
	}

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final TuiR5 tui = new TuiR5(
			new SmartcardIoConnection(),
			new TestTui.CachePasswordCallback("1111".toCharArray()) //$NON-NLS-1$
		);
		System.out.println(tui.getCardName());
		System.out.println(Arrays.asList(tui.getAliases()));
		System.out.println(tui.getPrivateKey(tui.getAliases()[0]));
	}

}
