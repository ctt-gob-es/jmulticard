package es.gob.jmulticard.card.gide.smartcafe;

import es.gob.jmulticard.card.PrivateKeyReference;

/** Clave privada de una tarjeta G&amp;D con Applet PKCS#15.
 * La clase no contiene la clave privada en s&iacute;, sino una referencia a ella.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class SmartCafePrivateKeyReference implements PrivateKeyReference {

	private final int keyOrdinal;

	/** Construye una clave privada de una tarjeta G&amp;D con Applet PKCS#15 a partir
	 * de su ordinal de referencia
	 * @param ordinal Ordinal de referencia de la clave. */
	public SmartCafePrivateKeyReference(final Integer ordinal) {
		if (ordinal == null) {
			throw new IllegalArgumentException(
				"El ordinal de la clave no puede ser nulo" //$NON-NLS-1$
			);
		}
		this.keyOrdinal = ordinal.intValue();
	}

	/** Obtiene el identificador (ordinal) de la clave.
	 * @return Identificador (ordinal) de la clave. */
	public int getKeyOrdinal() {
		return this.keyOrdinal;
	}

	@Override
	public String toString() {
		return "Clave privada para G&D SmartCafe (con Applet PKCS#15) con ordinal " + this.keyOrdinal; //$NON-NLS-1$
	}

}
