package es.gob.jmulticard.card.pace;

import java.util.logging.Logger;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.apdu.connection.cwa14890.InvalidCryptographicChecksumException;
import es.gob.jmulticard.card.SmartCard;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessagingException;

/** Conexi&oacute;n PACE para establecimiento de canal seguro por NFC.
 * @author Sergio Mart&iacute;nez Rico. */
public final class PaceConnection extends Cwa14890OneV2Connection {

	private static final StatusWord INVALID_CRYPTO_CHECKSUM = new StatusWord((byte)0x66, (byte)0x88);

	/** Byte de valor m&aacute;s significativo que indica un <i>Le</i> incorrecto en la petici&oacute;n. */
	private static final byte MSB_INCORRECT_LE = (byte) 0x6C;

	/** Byte de valor m&aacute;s significativo que indica un <i>Le</i> incorrecto en la petici&oacute;n. */
	private final SecureMessaging sm;

	/** Conexi&oacute;n PACE para establecimiento de canal seguro por NFC.
	 * @param connection Conexi&oacute;n base sobre la que crear el nuevo canal.
	 * @param cryptoHelper Clase para el cifrado de datos.
	 * @param secMsg Clase contenedora de las variables para establecer el canal PACE (Kenc, Kmac, Ssc). */
	public PaceConnection(final ApduConnection connection, final CryptoHelper cryptoHelper, final SecureMessaging secMsg) {
		super(connection, cryptoHelper);
		this.sm = secMsg;
		this.subConnection = connection;
	}

	/** Abre el canal seguro con la tarjeta. La conexi&oacute;n se reiniciar&aacute; previamente
	 * a la apertura del canal. */
	@Override
	public void open() {
		// Mantenemos el canal como cerrado al ser unicamente un canal previo al canal seguro
		this.openState = false;
	}

	/** {@inheritDoc} */
	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		// Si es el comando para verificar el PIN se creara una instancia nueva de la clase
		// CommandApdu ya que la clase VerifyApduCommand no incluye la contrasena como parte
		// la APDU, sino en un attributo aparte
		final CommandApdu finalCommand = new CommandApdu(
			command.getCla(),
			command.getIns(),
			command.getP1(),
			command.getP2(),
			command.getData(),
			command.getLe()
		);

		if (SmartCard.DEBUG) {
			Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
				"APDU de comando en claro: " + HexUtils.hexify(finalCommand.getBytes(), true) //$NON-NLS-1$
			);
		}

		// Encriptacion de la APDU para su envio por el canal seguro
		final CommandApdu protectedApdu;
		try {
			protectedApdu = this.sm.wrap(finalCommand);
		}
		catch (final SecureMessagingException e) {
			throw new ApduConnectionException("No ha sido posible cifrar un mensaje seguro con el canal PACE: " + e); //$NON-NLS-1$
		}

		final ResponseApdu responseApdu = this.subConnection.transmit(protectedApdu);

		final ResponseApdu decipherApdu;
		try {
			decipherApdu = this.sm.unwrap(responseApdu);
		}
		catch (final SecureMessagingException e1) {
			throw new ApduConnectionException("No ha sido posible descifrar un mensaje seguro con el canal PACE: " + e1); //$NON-NLS-1$
		}

		if (SmartCard.DEBUG) {
			Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
				"APDU de respuesta en claro: " + HexUtils.hexify(decipherApdu.getBytes(), true) //$NON-NLS-1$
			);
		}

		if (INVALID_CRYPTO_CHECKSUM.equals(decipherApdu.getStatusWord())) {
			throw new InvalidCryptographicChecksumException();
		}

		// Si la APDU descifrada indicase que no se indico bien el tamano de la respuesta, volveriamos
		// a enviar el comando indicando la longitud correcta
		if (decipherApdu.getStatusWord().getMsb() == MSB_INCORRECT_LE) {
			command.setLe(decipherApdu.getStatusWord().getLsb());
			return transmit(command);
		}
		return decipherApdu;
	}
}
