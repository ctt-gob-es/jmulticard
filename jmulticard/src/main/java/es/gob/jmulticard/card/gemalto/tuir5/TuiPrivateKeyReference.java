package es.gob.jmulticard.card.gemalto.tuir5;

import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una TUI. La clase no contiene la clave privada en si, sino una referencia a ella
 * y una referencia a la propia TUI.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class TuiPrivateKeyReference implements PrivateKeyReference {

	private final byte keyIndex;

	/** Construye una clave privada de una TUI.
	 * @param index &Iacute;ndice hacia la clave privada */
	TuiPrivateKeyReference(final byte index) {
		this.keyIndex = index;
	}

	byte getIndex() {
		return this.keyIndex;
	}

	@Override
	public String toString() {
		return "Referencia a clave privada de TUI con el indice: " + Byte.toString(this.keyIndex); //$NON-NLS-1$
	}
}
