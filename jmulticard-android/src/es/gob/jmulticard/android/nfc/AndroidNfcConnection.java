package es.gob.jmulticard.android.nfc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionProtocol;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre NFC para Android.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class AndroidNfcConnection implements ApduConnection {

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
            throw new IllegalArgumentException("El tag NFC no puede ser nulo"); //$NON-NLS-1$
        }
        this.mIsoDep = IsoDep.get(tag);
        this.mIsoDep.connect();
        this.mIsoDep.setTimeout(ISODEP_TIMEOUT);

        // Retenemos la conexion hasta nuestro siguiente envio
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1) {
            NFCWatchdogRefresher.holdConnection(this.mIsoDep);
        }
    }

    @Override
    public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
        if (this.mIsoDep == null) {
            throw new ApduConnectionException(
                "No se puede transmitir sobre una conexion NFC cerrada" //$NON-NLS-1$
            );
        }
        if (command == null) {
            throw new IllegalArgumentException(
                "No se puede transmitir una APDU nula" //$NON-NLS-1$
            );
        }
        if(!this.mIsoDep.isConnected()) {
        	try {
				this.mIsoDep.connect();
			}
			catch (final IOException e) {
				throw new ApduConnectionException(
                    "Se ha producido un problema al intentar establecer la conexion por NFC: " + e, e //$NON-NLS-1$
                );
			}
        }

        if (DEBUG) {
            Log.d(TAG, "Enviada APDU:\n" + HexUtils.hexify(command.getBytes(), false)); //$NON-NLS-1$
        }

        final byte[] commandBytes;
        if (command instanceof VerifyApduCommand) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final byte[] bcomm = command.getBytes();
            final byte[] bdata = command.getData();
            baos.write(bcomm, 0, bcomm.length - 2);
            try {
                baos.write(new byte[]{(byte) bdata.length});
                baos.write(bdata);
            }
            catch (final IOException e) {
                throw new ApduConnectionException(
                    "Error preparando la APDU para su envio", //$NON-NLS-1$
                    e
                );
            }
            commandBytes = baos.toByteArray();
        }
        else {
            commandBytes = command.getBytes();
        }

        // Liberamos la conexion para transmitir
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1) {
            NFCWatchdogRefresher.stopHoldingConnection();
        }

        //TODO: Fraccionar las APDU grandes con una envoltura?

        final byte[] bResp;
        try {
            bResp = this.mIsoDep.transceive(commandBytes);
        }
        catch (final IOException e) {
            // Evitamos que salga el PIN en la traza de excepcion
            throw new ApduConnectionException(
                "Error tratando de transmitir la APDU" + //$NON-NLS-1$
                    (command instanceof VerifyApduCommand ? " de verificacion de PIN" : //$NON-NLS-1$
                        " " + HexUtils.hexify(command.getBytes(), true)) +
                            " via NFC", //$NON-NLS-1$
                e
            );
        }
        finally {
            // Retenemos la conexion hasta nuestro siguiente envio
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1) {
                NFCWatchdogRefresher.holdConnection(this.mIsoDep);
            }
        }

        if (bResp.length < 2) {
            throw new ApduConnectionException(
                "No se ha recibido respuesta al envio del comando" //$NON-NLS-1$
            );
        }

        final ResponseApdu response = new ResponseApdu(bResp);

        if (response.getStatusWord().getMsb() == 97) {
            if (response.getData().length > 0) {
                final byte[] data = response.getData();
                final byte[] additionalData = transmit(
                    new GetResponseApduCommand(
                        (byte) 0, response.getStatusWord().getLsb()
                    )
                ).getBytes();
                final byte[] fullResponse = new byte[data.length + additionalData.length];
                System.arraycopy(data, 0, fullResponse, 0, data.length);
                System.arraycopy(
                    additionalData,
                    0,
                    fullResponse,
                    data.length,
                    additionalData.length
                );
                return new ResponseApdu(fullResponse);
            }
            return transmit(
                new GetResponseApduCommand((byte) 0, response.getStatusWord().getLsb())
            );
        }
        if (response.getStatusWord().getMsb() == 108 && command.getCla() == 0) {
            command.setLe(response.getStatusWord().getLsb());
            return transmit(command);
        }

        if (DEBUG) {
            Log.d(TAG, "Respuesta:\n" + HexUtils.hexify(response.getBytes(), false)); //$NON-NLS-1$
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
                "Error intentando abrir la comunicacion NFC contra la tarjeta: " + e, e //$NON-NLS-1$
            );
        }
    }

    @Override
    public void close() throws ApduConnectionException {
        // Liberamos la conexion
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.GINGERBREAD_MR1) {
            NFCWatchdogRefresher.stopHoldingConnection();
        }
        try{
        	this.mIsoDep.close();
        }
	    catch(final IOException ioe) {
        	throw new ApduConnectionException(
                "Error indefinido cerrando la conexion con la tarjeta: " + ioe, ioe //$NON-NLS-1$
            );
        }
    }

    @Override
    public byte[] reset() throws ApduConnectionException {
    	//No se cierran las conexiones por NFC
        if (this.mIsoDep != null) {
        	if (this.mIsoDep.getHistoricalBytes() != null) {
        		return this.mIsoDep.getHistoricalBytes();
        	}
		    return this.mIsoDep.getHiLayerResponse();
        }
        throw new ApduConnectionException(
            "Error indefinido reiniciando la conexion con la tarjeta" //$NON-NLS-1$
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
		return "Interfaz ISO-DEP NFC de Android"; //$NON-NLS-1$
	}

	@Override
	public void setTerminal(final int t) {
		// Vacio
	}

	@Override
	public boolean isOpen() {
		return this.mIsoDep.isConnected();
	}

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		// No hace nada
	}

    @Override
    public ApduConnection getSubConnection() {
        return null; // Esta es la conexion de mas bajo nivel
    }
}
