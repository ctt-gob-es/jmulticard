package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor PIN para inicializaci&oacute;n de un canal PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class WirelessInitializerPin implements WirelessInitializer {

	/** PIN del eMRTD. */
	private final char[] pin;

	/** Construye un CAN para inicializaci&oacute;n de un canal PACE.
	 * @param personalIdentificationNumber PIN. */
	public WirelessInitializerPin(final char[] personalIdentificationNumber) {
		if (personalIdentificationNumber == null || personalIdentificationNumber.length < 1) {
			throw new IllegalArgumentException("El valor del PIN no puede ser nulo ni vacio"); //$NON-NLS-1$
		}
		pin = personalIdentificationNumber;
	}

	@Override
	public  byte[] getBytes() {
		return HexUtils.charArrayToByteArray(pin);
	}

	@Override
	public String toString() {
		return new String(pin);
	}

	@Override
	public PacePasswordType getPasswordType() {
		return MseSetPaceAlgorithmApduCommand.PacePasswordType.PIN;
	}
}
