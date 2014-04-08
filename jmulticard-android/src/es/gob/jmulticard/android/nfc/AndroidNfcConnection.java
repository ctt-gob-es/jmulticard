package es.gob.jmulticard.android.nfc;

import android.nfc.tech.IsoDep;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre NFC para Android.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class AndroidNfcConnection implements ApduConnection {

	private static final int ISODEP_TIMEOUT = 5000;

	private final IsoDep iso;

	/** Crea una conexi&oacute;n con lector de tarjetas inteligentes implementado sobre NFC para Android.
	 * @param isoDep Objeto de conexi&oacute;n ISO-DEP (ISO 14443-4) */
	public AndroidNfcConnection(final IsoDep isoDep) {
		if (isoDep == null) {
			throw new IllegalArgumentException("El objeto ISO-DEP (ISO 14443-4) no puede ser nulo"); //$NON-NLS-1$
		}
		this.iso = isoDep;
	}

	@Override
	public void open() throws ApduConnectionException {
		if (!this.iso.isConnected()) {
			try {
				this.iso.connect();
			}
			catch (final Exception e) {
				throw new IllegalArgumentException(
					"No se ha podido abrir la conexion ISO-DEP (ISO 14443-4): " + e, e //$NON-NLS-1$
				);
			}
			this.iso.setTimeout(ISODEP_TIMEOUT);
		}
	}

	@Override
	public void close() throws ApduConnectionException {
		try {
			this.iso.close();
		}
		catch (final Exception e) {
			throw new ApduConnectionException(
				"No se ha podido cerrar la conexion ISO-DEP: " + e, e //$NON-NLS-1$
			);
		}
	}

	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		if (command == null) {
			throw new IllegalArgumentException("La APDU a transmitir no puede ser nula"); //$NON-NLS-1$
		}
		if (!this.iso.isConnected()) {
			open();
		}
		try {
			return new ResponseApdu(
				this.iso.transceive(command.getBytes())
			);
		}
		catch (final Exception e) {
			throw new ApduConnectionException(
				"Error transmitiendo la APDU '" + HexUtils.hexify(command.getBytes(), true) + "': " + e, //$NON-NLS-1$ //$NON-NLS-2$
				e
			);
		}
	}

	@Override
	public byte[] reset() throws ApduConnectionException {
		return this.iso.getHistoricalBytes();
	}

	@Override
	public void addCardConnectionListener(final CardConnectionListener ccl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeCardConnectionListener(final CardConnectionListener ccl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long[] getTerminals(final boolean onlyWithCardPresent) throws ApduConnectionException {
		return new long[] { 0 };
	}

	@Override
	public String getTerminalInfo(final int terminal) throws ApduConnectionException {
		return "Interfaz ISO-DEP NFC de Android"; //$NON-NLS-1$
	}

	@Override
	public void setTerminal(final int t) {
		// Vacio
	}

	@Override
	public boolean isOpen() {
		return this.iso.isConnected();
	}

}
