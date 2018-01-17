package es.gob.jmulticard.card.pace;

/** Valor de inicializaci&oacute;n de un canal PACE.
 * T&iacute;picamente un CAN o una MRZ.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class PaceInitializer {

	private final String value;

	protected PaceInitializer(final String val) {
		if (val == null || val.isEmpty()) {
			throw new IllegalArgumentException(
				"El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		this.value = val;
	}

	@Override
	public String toString() {
		return this.value;
	}

	/** Obtiene la codificaci&oacute;n binaria del valor con la codificaci&oacute;n por defecto.
	 * @return Codificaci&oacute;n binaria del valor con la codificaci&oacute;n por defecto. */
	public byte[] getBytes() {
		return this.value.getBytes();
	}

}
