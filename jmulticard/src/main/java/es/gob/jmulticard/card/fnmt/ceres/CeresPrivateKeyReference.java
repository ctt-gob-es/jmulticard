package es.gob.jmulticard.card.fnmt.ceres;

import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una tarjeta CERES. La clase no contiene la clave privada en si, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class CeresPrivateKeyReference implements PrivateKeyReference {

	private final byte index;

	/** Crea una referencia a una clave privada de tarjeta CERES.
	 * @param idx &Iacute;ndice interno de la clave. */
	public CeresPrivateKeyReference(final byte idx) {
		this.index = idx;
	}

	/** Recupera el &iacute;ndice de la clave.
	 * @return &Iacute;ndice de la clave. */
	public byte getKeyIndex() {
		return this.index;
	}

	@Override
	public String toString() {
		return "Clave privada de tarjeta CERES con indoce: " + Byte.toString(this.index); //$NON-NLS-1$
	}
}
