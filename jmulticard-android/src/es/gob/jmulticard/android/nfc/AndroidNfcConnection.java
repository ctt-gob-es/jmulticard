package com.fnmt.certrequest.crypto.jmulticard;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.AbstractApduConnectionIso7816;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionProtocol;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;

import java.io.IOException;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre NFC para Android.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class AndroidNfcConnection extends AbstractApduConnectionIso7816 {

    private static final boolean DEBUG = false;
    private static final String TAG = AndroidNfcConnection.class.getSimpleName();

    private static final int ISODEP_TIMEOUT = 3000;

    private final IsoDep mIsoDep;

    /** Constructor de la clase para la gesti&oacute;n de la conexi&oacute;n por NFC.
     * @param tag <code>Tag</code> para obtener el objeto <code>IsoDep</code> y establecer la
     *            conexi&oacute;n.
     * @throws IOException Si falla el establecimiento de la conexi&oacute;n. */
    public AndroidNfcConnection(final Tag tag) throws IOException {
        if (tag == null) {
            throw new IllegalArgumentException("El tag NFC no puede ser nulo");
        }
        this.mIsoDep = IsoDep.get(tag);
        this.mIsoDep.connect();
        this.mIsoDep.setTimeout(ISODEP_TIMEOUT);

        // Retenemos la conexion hasta nuestro siguiente envio
	  // Solo en la versiones de Android afectadas por el error https://issuetracker.google.com/issues/36977343
        if (
		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
		android.os.Build.VERSION.SDK_INT <  android.os.Build.VERSION_CODES.P
	  ) {
            NFCWatchdogRefresher.holdConnection(this.mIsoDep);
        }
    }

    @Override
    public ResponseApdu internalTransmit(byte[] apdu) throws ApduConnectionException {
        if (this.mIsoDep == null) {
            throw new ApduConnectionException(
                "No se puede transmitir sobre una conexion NFC cerrada"
            );
        }

	  final boolean isChv = apdu[1] == VerifyApduCommand.INS_VERIFY;

        if (DEBUG) {
            Log.d(TAG, "Se va a enviar la APDU:\n" + (isChv ? "Verificacion de PIN" : HexUtils.hexify(apdu, apdu.length > 32)));
        }

        // Liberamos la conexion para transmitir.
	  // Solo en la versiones de Android afectadas por el error https://issuetracker.google.com/issues/36977343
        if (
		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
		android.os.Build.VERSION.SDK_INT <  android.os.Build.VERSION_CODES.P
	  ) {
            NFCWatchdogRefresher.stopHoldingConnection();
        }

        final byte[] bResp;
        try {
            bResp = this.mIsoDep.transceive(apdu);
        }
        catch (final IOException e) {
            // Evitamos que salga el PIN en la traza de excepcion
            throw new ApduConnectionException(
			"Error tratando de transmitir la APDU\n" + (isChv ? "Verificacion de PIN" : HexUtils.hexify(apdu, apdu.length > 32)),
                    	e
            );
        }
        finally {
            // Retenemos la conexion hasta nuestro siguiente envio
		// Solo en la versiones de Android afectadas por el error https://issuetracker.google.com/issues/36977343
            if (
			android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
			android.os.Build.VERSION.SDK_INT <  android.os.Build.VERSION_CODES.P
	  	) {
                NFCWatchdogRefresher.holdConnection(this.mIsoDep);
            }
        }

        final ResponseApdu response = new ResponseApdu(bResp);

        if (DEBUG) {
            Log.d(TAG, "Respuesta:\n" + HexUtils.hexify(response.getBytes(), bResp.length > 32));
        }

        return response;
    }

    @Override
    public void open() throws ApduConnectionException {
        try {
            if (!this.mIsoDep.isConnected()) {
                this.mIsoDep.connect();
            }
        }
        catch (final Exception e) {
            throw new ApduConnectionException(
                "Error intentando abrir la comunicacion NFC contra la tarjeta", e
            );
        }
    }

    @Override
    public void close() throws ApduConnectionException {
        // Liberamos la conexion
        if (
		android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1 &&
		android.os.Build.VERSION.SDK_INT <  android.os.Build.VERSION_CODES.P
	  ) {
            NFCWatchdogRefresher.stopHoldingConnection();
        }
        try {
        	this.mIsoDep.close();
        }
	  catch(final IOException ioe) {
        	throw new ApduConnectionException(
                "Error indefinido cerrando la conexion con la tarjeta", ioe
            );
        }
    }

    @Override
    public byte[] reset() throws ApduConnectionException {
    	  // No se cierran las conexiones por NFC
        if (this.mIsoDep != null) {
        	if (this.mIsoDep.getHistoricalBytes() != null) {
        		return this.mIsoDep.getHistoricalBytes();
        	}
		return this.mIsoDep.getHiLayerResponse();
        }
        throw new ApduConnectionException(
            "Error indefinido reiniciando la conexion con la tarjeta"
        );
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
	public long[] getTerminals(final boolean onlyWithCardPresent) {
		return new long[] { 0 };
	}

	@Override
	public String getTerminalInfo(final int terminal) {
		return "Interfaz ISO-DEP NFC de Android";
	}

	@Override
	public void setTerminal(final int t) {
		// Vacio, solo hay un terminal NFC por terminal
	}

	@Override
	public boolean isOpen() {
		return this.mIsoDep.isConnected();
	}

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		// No hace nada, siempre es T=CL
	}

    @Override
    public ApduConnection getSubConnection() {
        return null; // Esta es la conexion de mas bajo nivel
    }

    @Override
    public int getMaxApduSize() {
        return 0xff;
    }
}
