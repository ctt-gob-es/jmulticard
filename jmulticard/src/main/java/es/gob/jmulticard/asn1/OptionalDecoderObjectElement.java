package es.gob.jmulticard.asn1;

/** Tipo de objeto ASN&#46;1 gen&eacute;rico opcional dentro de un objeto compuesto.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class OptionalDecoderObjectElement {

	private final Class<? extends DecoderObject> elementType;
	private final boolean optional;

	/** Construye un tipo de objeto ASN&#46;1 gen&eacute;rico opcional dentro de un objeto compuesto.
	 * @param type Tipo de objeto ASN&#46;1
	 * @param opt <code>true</code> si este elemento es opcional dentro de un objeto compuesto,
	 *            <code>false</code> en caso contrario */
	public OptionalDecoderObjectElement(final Class<? extends DecoderObject> type, final boolean opt) {
		if (type == null && !opt) {
			throw new IllegalArgumentException(
				"El tipo de elemento ASN.1 no puede ser nulo cuando el elemento no es opcional" //$NON-NLS-1$
			);
		}
		this.elementType = type;
		this.optional = opt;
	}

	/** Optiene el tipo del elemento ASN&#46;1.
	 * @return Tipo del elemento ASN&#46;1 */
	public Class<? extends DecoderObject> getElementType() {
		return this.elementType;
	}

	/** Indica si el elemento es opcional dentro de un objeto compuesto.
	 * @return <code>true</code> si este elemento es opcional dentro de un objeto compuesto,
	 *          <code>false</code> en caso contrario */
	public boolean isOptional() {
		return this.optional;
	}

}
