package es.gob.jmulticard.card.fnmt.ceres;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una tarjeta CERES. La clase no contiene la clave privada en si, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class CeresPrivateKeyReference implements PrivateKeyReference {

	private final byte reference;
	private final int keySize;

	/** Crea una referencia a una clave privada de tarjeta CERES.
	 * @param r Referencia interna de la clave.
	 * @param kSize Tama&ntilde;o en bits de la clave privada. */
	public CeresPrivateKeyReference(final byte r, final int kSize) {
		this.reference = r;
		this.keySize = kSize;
	}

	/** Recupera la referencia de la clave.
	 * @return Referencia de la clave. */
	public byte getKeyReference() {
		return this.reference;
	}

	/** Obtiene el tam&ntilde;o en bits de la clave.
	 * @return Tam&ntilde;o en bits de la clave. */
	public int getKeyBitSize() {
		return this.keySize;
	}

	@Override
	public String toString() {
		return "Clave privada de tarjeta CERES de " + this.keySize + " bits con referencia: 0x" + HexUtils.hexify(new byte[] { this.reference }, false); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
