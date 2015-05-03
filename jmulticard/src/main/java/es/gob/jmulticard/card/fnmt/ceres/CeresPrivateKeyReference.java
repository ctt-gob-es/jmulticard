package es.gob.jmulticard.card.fnmt.ceres;

import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una tarjeta CERES. La clase no contiene la clave privada en si, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class CeresPrivateKeyReference implements PrivateKeyReference {

	private final String path;

	/** Crea una referencia a una clave privada de tarjeta CERES.
	 * @param p Ruta interna de la clave. */
	public CeresPrivateKeyReference(final String p) {
		this.path = p;
	}

	/** Recupera el &iacute;ndice de la clave.
	 * @return Ruta de la clave. */
	public String getKeyIndex() {
		return this.path;
	}

	@Override
	public String toString() {
		return "Clave privada de tarjeta CERES con ruta: " + this.path; //$NON-NLS-1$
	}
}
