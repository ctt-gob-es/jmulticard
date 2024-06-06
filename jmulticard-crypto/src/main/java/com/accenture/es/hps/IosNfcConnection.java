package com.accenture.es.hps;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.ApduConnectionProtocol;

/** Conexi&oacute;n con tarjeta inteliente.
 * Para ser reimplementada en Apple iOS.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class IosNfcConnection implements ApduConnection {

	private IosNfcConnectionImpl iosConn;

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		// Vacio
	}

	@Override
	public void open() throws ApduConnectionException {
    	if (isOpen()) {
    		return;
    	}
    	iosConn = new IosNfcConnectionImpl();
    	if (iosConn.open() != 0) {
    		throw new ApduConnectionException("Error abriendo la conexion NFC en iOS"); //$NON-NLS-1$
    	}
	}

	@Override
	public void close() throws ApduConnectionException {
		if (isOpen() && iosConn.close() != 0) {
			throw new ApduConnectionException("Error cerrando la conexion NFC en iOS"); //$NON-NLS-1$
		}
	}

	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		if (!isOpen()) {
			throw new ApduConnectionException("No se puede transmitir un comando en una conexion cerrada"); //$NON-NLS-1$
		}
		final WrappedResponseApdu res = iosConn.transmit(command);
		if (res.getError() != 0) {
			throw new ApduConnectionException("Error transmitiendo el error a la tarjeta por NFC en iOS"); //$NON-NLS-1$
		}
		return res.getResponseApdu();
	}

	@Override
	public byte[] reset() throws ApduConnectionException {
		if (isOpen()) {
			final WrappedAtr res = iosConn.reset();
			if (res.getError() != 0) {
				throw new ApduConnectionException("Error obteniendo el ATR de la tarjeta"); //$NON-NLS-1$
			}
			return res.getAtr();
		}
		throw new ApduConnectionException("No se puede obtener el ATR de una tarjeta sobre una conexion cerrada"); //$NON-NLS-1$
	}

	@Override
	public long[] getTerminals(final boolean onlyWithCardPresent) {
		return new long[] { 0L };
	}

	@Override
	public String getTerminalInfo(final int terminal) {
		return "Interfaz NFC de Apple iOS"; //$NON-NLS-1$
	}

	@Override
	public void setTerminal(final int t) {
		// Vacio
	}

	@Override
	public boolean isOpen() {
		return iosConn != null && iosConn.isOpen();
	}

	@Override
	public ApduConnection getSubConnection() {
		return null; // Es conexion de mas bajo nivel
	}

	static final class WrappedResponseApdu {

		private final ResponseApdu apdu;
		private final int error;

		WrappedResponseApdu(final ResponseApdu tApdu, final int err) {
			apdu = tApdu;
			error = err;
		}

		int getError() {
			return error;
		}

		ResponseApdu getResponseApdu() {
			return apdu;
		}
	}

	static final class WrappedAtr {

		private final byte[] atr;
		private final int error;

		WrappedAtr(final byte[] cardAtr, final int err) {
			atr = cardAtr != null ? cardAtr.clone() : new byte[] { (byte) 0x00 };
			error = err;
		}

		int getError() {
			return error;
		}

		byte[] getAtr() {
			return atr != null ? atr.clone() : new byte[] { (byte) 0x00 };
		}
	}
}
