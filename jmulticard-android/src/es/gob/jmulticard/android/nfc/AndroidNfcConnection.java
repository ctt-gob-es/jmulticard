package es.gob.jmulticard.android.nfc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
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
    static final String TAG = "NfcConnection"; //$NON-NLS-1$
    private static IsoDep misoDep;
    private static final byte TAG_RESPONSE_PENDING = 97;
    private static final byte TAG_RESPONSE_INVALID_LENGTH = 108;
    private static boolean DEBUG = true;

    public IsoDep getIsoDep() {
        return misoDep;
    }

    public AndroidNfcConnection() {
        misoDep = null;
    }

    public AndroidNfcConnection(final Tag tag) throws IOException {
        if (tag == null) {
            throw new IllegalArgumentException("El tag NFC no puede ser nulo"); //$NON-NLS-1$
        }
        misoDep = IsoDep.get(tag);
        misoDep.connect();
        misoDep.setTimeout(3000);
    }

    @Override
    public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
        if (misoDep == null) {
            throw new ApduConnectionException("No se puede transmitir sobre una conexion NFC cerrada"); //$NON-NLS-1$
        }
        if (command == null) {
            throw new IllegalArgumentException("No se puede transmitir una APDU nula"); //$NON-NLS-1$
        }
        if(!misoDep.isConnected()) {
        	try {
				misoDep.connect();
			} catch (final IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        }
        try {
            ResponseApdu response = null;
            if (command instanceof VerifyApduCommand) {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final byte[] bcomm = command.getBytes();
                final byte[] bdata = command.getData();
                baos.write(bcomm, 0, bcomm.length - 2);
                baos.write(new byte[]{(byte)bdata.length});
                baos.write(bdata);
                byte[] bResp = new byte[]{0, 0};
                try {
                    bResp = misoDep.transceive(baos.toByteArray());
                    if (bResp.length < 2) {
                        throw new ApduConnectionException("No se ha recibido respuesta al env\u00edo del comando."); //$NON-NLS-1$
                    }
                }
                catch (final IOException e) {
                    e.printStackTrace();
                }
                response = new ResponseApdu(bResp);
            } else {
            	byte[] bResp = new byte[]{0, 0};
                try {
                    bResp = misoDep.transceive(command.getBytes());
                    if (bResp.length < 2) {
                        throw new ApduConnectionException("No se ha recibido respuesta al env\u00edo del comando."); //$NON-NLS-1$
                    }
                }
                catch (final IOException e) {
                    e.printStackTrace();
                }
                response = new ResponseApdu(bResp);
            }
            if (response.getStatusWord().getMsb() == 97) {
                if (response.getData().length > 0) {
                    final byte[] data = response.getData();
                    final byte[] additionalData = this.transmit(new GetResponseApduCommand((byte) 0, response.getStatusWord().getLsb())).getBytes();
                    final byte[] fullResponse = new byte[data.length + additionalData.length];
                    System.arraycopy(data, 0, fullResponse, 0, data.length);
                    System.arraycopy(additionalData, 0, fullResponse, data.length, additionalData.length);
                    return new ResponseApdu(fullResponse);
                }
                return this.transmit(new GetResponseApduCommand((byte) 0, response.getStatusWord().getLsb()));
            }
            if (response.getStatusWord().getMsb() == 108 && command.getCla() == 0) {
                command.setLe(response.getStatusWord().getLsb());
                return this.transmit(command);
            }
            return response;
        }
        catch (final Exception e) {
            throw new ApduConnectionException("Error tratando de transmitir la APDU " + HexUtils.hexify(command.getBytes(), true) + " al lector NFC.", e); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }

    @Override
    public void open() throws ApduConnectionException {
        try {
            if (!misoDep.isConnected()) {
                misoDep.connect();
            }
        }
        catch (final Exception e) {
            throw new ApduConnectionException("Error intentando abrir la comunicaci\u00f3n NFC contra la tarjeta.", e); //$NON-NLS-1$
        }
    }

    @Override
    public void close() throws ApduConnectionException {
        this.closeConnection(false);
    }

    private void closeConnection(final boolean resetCard) throws ApduConnectionException {
        if (misoDep != null) {
            try {
                if (misoDep.isConnected()) {
                    misoDep.close();
                }
            }
            catch (final Exception e) {
                throw new ApduConnectionException("Error intentando cerrar el objeto de tarjeta inteligente, la conexion puede quedar abierta pero inutil", e); //$NON-NLS-1$
            }
        }
    }

    @Override
    public byte[] reset() throws ApduConnectionException {
        this.closeConnection(true);
        this.open();
        if (misoDep != null) {
        	if (misoDep.getHistoricalBytes() != null) {
        		return misoDep.getHistoricalBytes();
        	}
			return misoDep.getHiLayerResponse();
        }
        throw new ApduConnectionException("Error indefinido reiniciando la conexion con la tarjeta"); //$NON-NLS-1$
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
		return misoDep.isConnected();
	}

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		// No hace nada
	}
}
