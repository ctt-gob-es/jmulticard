package es.gob.jmulticard.card.fnmt.ceres;

import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una tarjeta CERES. La clase no contiene la clave privada en si, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class CeresPrivateKeyReference implements PrivateKeyReference {

	private final Location keyPath;

	/** Crea una referencia a una clave privada de tarjeta CERES.
	 * @param path Ruta interna de la clave. */
	public CeresPrivateKeyReference(final Location path) {
		this.keyPath = path;
	}

	/** Recupera la ruta de la clave.
	 * @return Ruta de la clave. */
	public Location getKeyPath() {
		return this.keyPath;
	}

	@Override
	public String toString() {
		return "Clave privada de tarjeta CERES con ruta: " + this.keyPath.toString(); //$NON-NLS-1$
	}
}
