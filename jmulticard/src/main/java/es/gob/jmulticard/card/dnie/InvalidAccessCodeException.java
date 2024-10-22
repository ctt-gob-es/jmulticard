package es.gob.jmulticard.card.dnie;

import es.gob.jmulticard.connection.ApduConnectionException;

/**
 * Excepci&oacute;n que se&ntilde;ala cuando no se puede completar la conexi&oacute;n con una
 * tarjeta porque el c&oacute;digo de acceso, como el CAN del DNI o el MRZ del pasaporte
 * electr&oacute;nico, no es correcto.
 */
public class InvalidAccessCodeException extends ApduConnectionException {

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = 5878922643296036682L;

	/**
	 * Construye una excepci&oacute;n para indicar que no se pudo conectar con la tarjeta debido a
	 * que el c&uacute;digo de acceso (CAN, MRZ...) no es v&aacute;lido.
     * @param message Mensaje de excepci&oacute;n.
     * @param cause Causa de la excepci&oacute;n.
     */
    public InvalidAccessCodeException(final String message, final Throwable cause) {
        super(message, cause);
    }

	/**
	 * Construye una excepci&oacute;n para indicar que no se pudo conectar con la tarjeta debido a
	 * que el c&uacute;digo de acceso (CAN, MRZ...) no es v&aacute;lido.
     * @param message Mensaje de excepci&oacute;n.
     */
    public InvalidAccessCodeException(final String message) {
        super(message);
    }

	/**
	 * Construye una excepci&oacute;n para indicar que no se pudo conectar con la tarjeta debido a
	 * que el c&uacute;digo de acceso (CAN, MRZ...) no es v&aacute;lido.
     * @param cause Causa de la excepci&oacute;n.
     */
    public InvalidAccessCodeException(final Throwable cause) {
        super(cause);
    }
}
