package es.gob.jmulticard.connection;

/** Excepci&oacute;n lanzada cuando se intenta acceder a un lector que ya no est&aacute; disponible.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Jose Luis Escanciano. */
public final class UnavailableReaderException extends ApduConnectionException {

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = 4033742751748929273L;

	/** Crea una excepci&oacute;n que indica que se intenta acceder a un lector que ya no est&aacute; disponible.
	 * @param message Mensaje de la excepci&oacute;n. */
	public UnavailableReaderException(final String message) {
		super(message);
	}

	/** Crea una excepci&oacute;n que indica que se intenta acceder a un lector que ya no est&aacute; disponible.
	 * @param message Mensaje de la excepci&oacute;n.
	 * @param cause Causa inicial de la excepci&oacute;n. */
	public UnavailableReaderException(final String message, final Throwable cause) {
		super(message, cause);
	}
}