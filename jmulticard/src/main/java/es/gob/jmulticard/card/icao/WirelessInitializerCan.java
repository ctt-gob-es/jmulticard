package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor CAN para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public final class WirelessInitializerCan implements WirelessInitializer {

	/** CAN del eMRTD. */
	private transient final String can;

	/** Construye un CAN para inicializaci&oacute;n de un canal PACE.
	 * @param cardAccessNumber CAN. */
	public WirelessInitializerCan(final String cardAccessNumber) {
		if (cardAccessNumber == null || cardAccessNumber.isEmpty()) {
			throw new IllegalArgumentException(
				"El valor no puede ser nulo ni vacio" //$NON-NLS-1$
			);
		}
		this.can = cardAccessNumber;
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
