package es.gob.jmulticard.card.pace;

/** Excepci&oacute;n de MRZ err&oacute;neo introducido.
 * @author Ignacio Mar&iacute;n
 */
public final class MalformedMrzException extends PaceException {

	private static final long serialVersionUID = 437348879325857134L;

	/** Excepci&oacute;n de MRZ err&oacute;neo introducido.
	 * @param description Descripci&oacute;n del error
	 */
	public MalformedMrzException(String description) {
		super(description);
	}

}
