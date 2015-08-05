package es.gob.jmulticard.card.pace;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand;

/** Utilidades para el establecimiento de un canal <a href="https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html">PACE</a>
 * (Password Authenticated Connection Establishment).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceChannelHelper {

	private PaceChannelHelper() {
		// No instanciable
	}

	/** Abre un canal PACE mediante el CAN (<i>Card Access Number</i>).
	 * @param cla Clase de APDU para los comandos de establecimiento de canal.
	 * @param conn Conexi&oacute;n hacia la tarjeta inteligente.
	 * @throws ApduConnectionException Si hay problemas de conexi&oacute;n con la tarjeta.
	 * @throws PaceException Si hay problemas en la apertura del canal. */
	public static void openPaceChannel(final byte cla, final ApduConnection conn) throws ApduConnectionException, PaceException {
		if (conn == null) {
			throw new IllegalArgumentException(
				"El canal de conexion no puede ser nulo" //$NON-NLS-1$
			);
		}
		if (!conn.isOpen()) {
			conn.open();
		}

		ResponseApdu res;

		// 1 - Establecemos el algoritmo para PACE
		res = conn.transmit(
			new MseSetPaceAlgorithmApduCommand(
				cla,
				MseSetPaceAlgorithmApduCommand.PaceAlgorithmOid.PACE_ECDH_GM_AES_CBC_CMAC_128
			)
		);

		if (!res.isOk()) {
			throw new PaceException(
				"Error estableciendo el algoritmo del protocolo PACE: " + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
			);
		}
	}

}
