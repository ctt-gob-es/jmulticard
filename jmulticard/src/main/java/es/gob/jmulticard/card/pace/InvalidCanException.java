package es.gob.jmulticard.card.pace;

/** Excepci&oacute;n de CAN err&oacute;neo introducido.
 * @author Sergio Mart&iacute;nez Rico
 */
public final class InvalidCanException extends PaceException {

	private static final long serialVersionUID = 8254462304692038281L;

	/** Excepci&oacute;n de CAN err&oacute;neo introducido.
	 * @param description Descripci&oacute;n del error
	 */
	public InvalidCanException(String description) {
		super(description);
	}

}
