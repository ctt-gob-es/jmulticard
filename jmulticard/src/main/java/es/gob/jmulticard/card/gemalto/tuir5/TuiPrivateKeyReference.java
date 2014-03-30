package es.gob.jmulticard.card.gemalto.tuir5;

import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una TUI. La clase no contiene la clave privada en si, sino una referencia a ella
 * y una referencia a la propia TUI.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class TuiPrivateKeyReference implements PrivateKeyReference {

	private final TuiR5 tuiCard;

	/** Construye una clave privada de una TUI.
	 * @param tui Referencia a la tarjeta TUI que contiene la clave privada */
	public TuiPrivateKeyReference(final TuiR5 tui) {
		this.tuiCard = tui;
	}

	/** Obtiene la tarjeta TUI que contiene la clave privada referenciada por esta clase.
	 * @return Tarjeta TUI que contiene la clave privada referenciada por esta clase */
	public TuiR5 getTuiCard() {
		return this.tuiCard;
	}

}
