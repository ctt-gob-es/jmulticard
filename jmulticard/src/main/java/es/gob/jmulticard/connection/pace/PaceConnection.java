package es.gob.jmulticard.connection.pace;

import java.util.logging.Logger;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.card.AbstractSmartCard;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.connection.cwa14890.InvalidCryptographicChecksumException;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessagingException;

/** Conexi&oacute;n PACE para establecimiento de canal seguro por NFC.
 * @author Sergio Mart&iacute;nez Rico
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceConnection extends Cwa14890OneV2Connection {

	private static final StatusWord INVALID_CRYPTO_CHECKSUM = new StatusWord((byte)0x66, (byte)0x88);

	/** Octeto de valor m&aacute;s significativo que indica un <i>Le</i> incorrecto en la petici&oacute;n. */
	private static final byte MSB_INCORRECT_LE = (byte) 0x6C;

	/** Octeto de valor m&aacute;s significativo que indica un <i>Le</i> incorrecto en la petici&oacute;n. */
	private transient final SecureMessaging sm;

	/** Conexi&oacute;n PACE para establecimiento de canal seguro por NFC.
	 * @param connection Conexi&oacute;n base sobre la que crear el nuevo canal.
	 * @param cryptoHlpr Clase para el cifrado de datos.
	 * @param secMsg Clase contenedora de las variables para establecer el canal PACE (Kenc, Kmac, Ssc). */
	public PaceConnection(final ApduConnection connection,
			              final CryptoHelper cryptoHlpr,
			              final SecureMessaging secMsg) {
		super(connection, cryptoHlpr);
		sm = secMsg;
		subConnection = connection;
	}

	@Override
	public String toString() {
    	return "Conexion de tipo PACE sobre " + getSubConnection(); //$NON-NLS-1$
    }

	/** Abre el canal seguro con la tarjeta. La conexi&oacute;n se reiniciar&aacute; previamente
	 * a la apertura del canal. */
	@Override
	public void open() {
		openState = true;
	}

	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		// Si es el comando para verificar el PIN se creara una instancia nueva de la clase
		// CommandApdu ya que la clase StcmVerifyApduCommand no incluye la contrasena como parte
		// la APDU, sino en un attributo aparte
		final CommandApdu finalCommand = new CommandApdu(
			command.getCla(),
			command.getIns(),
			command.getP1(),
			command.getP2(),
			command.getData(),
			command.getLe()
		);

		final boolean isChv = finalCommand.getIns() == VerifyApduCommand.INS_VERIFY;

		if (AbstractSmartCard.DEBUG) {
			Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
				"APDU de comando en claro: " + //$NON-NLS-1$
					(isChv ? "Verificacion de PIN" : HexUtils.hexify(finalCommand.getBytes(), true)) //$NON-NLS-1$
			);
		}

		// Encriptacion de la APDU para su envio por el canal seguro
		final CommandApdu protectedApdu;
		try {
			protectedApdu = sm.wrap(finalCommand);
		}
		catch (final SecureMessagingException e) {
			throw new ApduConnectionException(
				"No ha sido posible cifrar un mensaje seguro con el canal PACE", e //$NON-NLS-1$
			);
		}

		final ResponseApdu responseApdu = subConnection.transmit(protectedApdu);

		// Ignoramos los errores 62-82 (lectura fuera de limites) por ser comunes y estar tratados especificamente
		if (!responseApdu.getStatusWord().isOk() && !new StatusWord((byte) 0x62, (byte) 0x82).equals(responseApdu.getStatusWord())) {
			throw new ApduConnectionException(
				"Error transmitiendo la APDU cifrada:\n" +            //$NON-NLS-1$
					"Error: " + responseApdu.getStatusWord() + '\n' + //$NON-NLS-1$
					"Respuesta:\n" + responseApdu + '\n' +            //$NON-NLS-1$
					"Comando cifrado:\n" + (isChv ? "Verificacion de PIN" : protectedApdu) + '\n' + //$NON-NLS-1$ //$NON-NLS-2$
					"Comando en claro:\n" + (isChv ? "Verificacion de PIN" : finalCommand) + '\n'   //$NON-NLS-1$ //$NON-NLS-2$
			);
		}

		final ResponseApdu decipherApdu;
		try {
			decipherApdu = sm.unwrap(responseApdu);
		}
		catch (final SecureMessagingException e1) {
			throw new ApduConnectionException(
				"No ha sido posible descifrar un mensaje seguro con el canal PACE", e1 //$NON-NLS-1$
			);
		}

		if (AbstractSmartCard.DEBUG) {
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
