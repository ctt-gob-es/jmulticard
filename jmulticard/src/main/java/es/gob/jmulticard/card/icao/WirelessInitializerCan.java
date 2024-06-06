package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor CAN para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class WirelessInitializerCan implements WirelessInitializer {

	/** CAN del eMRTD. */
	private final String can;

	/** Construye un CAN para inicializaci&oacute;n de un canal PACE.
	 * @param cardAccessNumber CAN. */
	public WirelessInitializerCan(final String cardAccessNumber) {
		if (cardAccessNumber == null || cardAccessNumber.isEmpty()) {
			throw new IllegalArgumentException("El valor del CAN no puede ser nulo ni vacio"); //$NON-NLS-1$
		}
		can = cardAccessNumber;
	}

	@Override
	public  byte[] getBytes() {
		return can.getBytes();
	}

	@Override
	public String toString() {
		return can;
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.CAN;
	}
}
