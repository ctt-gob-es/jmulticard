package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;

/** Valor de inicializaci&oacute;n de un canal PACE.
 * T&iacute;picamente un CAN o una MRZ.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public interface WirelessInitializer {

	/** Obtiene la codificaci&oacute;n binaria del valor con la codificaci&oacute;n por defecto.
	 * @return Codificaci&oacute;n binaria del valor con la codificaci&oacute;n por defecto. */
	byte[] getBytes();

	/** Obtiene el tipo de contrase&ntilde;a asociada a esta inicializaci&oacute;n.
	 * @return tipo de contrase&ntilde;a. */
	PacePasswordType getPasswordType();
}
