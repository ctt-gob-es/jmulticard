package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor CAN para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public final class WirelessInitializerCan implements WirelessInitializer {

	private final String can;

	/** Construye un CAN para inicializaci&oacute;n de un canal PACE.
	 * @param can CAN. */
	public WirelessInitializerCan(final String can) {
		if (can == null || can.isEmpty()) {
			throw new IllegalArgumentException(
				"El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		this.can = can;
	}

	@Override
	public  byte[] getBytes() {
		return this.can.getBytes();
	}

	@Override
	public String toString() {
		return this.can;
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.CAN;
	}
}
