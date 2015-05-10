package es.gob.jmulticard.card.fnmt.ceres;

import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una tarjeta CERES. La clase no contiene la clave privada en si, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class CeresPrivateKeyReference implements PrivateKeyReference {

	private final String path;
	private final int keySize;

	/** Crea una referencia a una clave privada de tarjeta CERES.
	 * @param p Ruta interna de la clave.
	 * @param kSize Tama&ntilde;o en bits de la clave privada. */
	public CeresPrivateKeyReference(final String p, final int kSize) {
		this.path = p;
		this.keySize = kSize;
	}

	/** Recupera el &iacute;ndice de la clave.
	 * @return Ruta de la clave. */
	public String getKeyIndex() {
		return this.path;
	}

	/** Obtiene el tam&ntilde;o en bits de la clave.
	 * @return Tam&ntilde;o en bits de la clave. */
	public int getKeyBitSize() {
		return this.keySize;
	}

	@Override
	public String toString() {
		return "Clave privada de tarjeta CERES de " + this.keySize + " bits con ruta: " + this.path; //$NON-NLS-1$ //$NON-NLS-2$
	}
}
