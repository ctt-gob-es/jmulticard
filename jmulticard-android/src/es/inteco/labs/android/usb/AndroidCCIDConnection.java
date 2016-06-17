/*
 * Proyecto CCIDroid. Driver para utilizacion de tarjetas CCID en el sistema operativo
 * Android.
 *
 * El proyecto CCIDroid es un conector para la comunicacion entre sistemas Android y
 * lectores de SmartCard USB segun el estandar CCID. Diseno inicial desarrollado para
 * su integracion con el Controlador Java de la Secretaria de Estado de Administraciones
 * Publicas para el DNI electronico.
 *
 * Copyright (C) 2012 Instituto Nacional de las Tecnologias de la Comunicacion (INTECO)
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */

package es.inteco.labs.android.usb;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.util.Log;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionProtocol;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.UnavailableReaderException;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;
import es.inteco.labs.android.usb.device.SmartCardUsbDevice;
import es.inteco.labs.android.usb.device.exception.NotAvailableUSBDeviceException;
import es.inteco.labs.android.usb.device.exception.UsbDeviceException;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre Android USB Host API.
 * Basado en <code>es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection</code>.
 * @author Jose Luis Escanciano Garcia */
public final class AndroidCCIDConnection implements ApduConnection {

	private final SmartCardUsbDevice ccidReader;

	private static final boolean DEBUG = false;

	/** Construye una conexi&oacute;n con lector de tarjetas inteligentes implementado sobre Android USB Host API.
	 * @param usbManager Gestor de dispositivos USB del sistema
	 * @param reader Dispositivo USB de tipo CCID (lector de tarjetas).
	 * @throws UsbDeviceException */
	public AndroidCCIDConnection(final UsbManager usbManager, final UsbDevice reader) throws UsbDeviceException{
		if (!isCardReader(reader)) {
			throw new IllegalArgumentException(
				"Debe proporcionarse un lector de tarjetas CCID" //$NON-NLS-1$
			);
		}
		this.ccidReader = new SmartCardUsbDevice(usbManager, reader);
	}

	/** Indica si el dispositivo es un lector de tarjetas.
	 * @return <code>true</code> si es un dispositivo CCID, <code>false</code> en caso contrario */
	private static boolean isCardReader(final UsbDevice device) {
		if (device == null) {
			return false;
		}
		// SmartCard Device Class: http://www.usb.org/developers/defined_class/#BaseClass00h
		// SmartCard Interface Class: http://www.usb.org/developers/defined_class/#BaseClass0Bh
		if(device.getDeviceClass() == 0x00 && device.getInterface(0).getInterfaceClass() == 0x0B) {
			return true;
		}
		return false;
	}

	/** {@inheritDoc} */
	@Override
	public void open() throws ApduConnectionException {
		try {
			if(!isOpen()) {
				this.ccidReader.open();
			}
		}
		catch (final NotAvailableUSBDeviceException e) {
			throw new UnavailableReaderException("No se puede acceder al dispositivo USB: " + e, e); //$NON-NLS-1$
		}
	}

	/** {@inheritDoc} */
	@Override
	public void close() throws ApduConnectionException {
		if(isOpen()) {
			this.ccidReader.close();
		}
	}

    /** Etiqueta que indica que es necesario recuperar el resultado del comando anterior. */
    private static final byte TAG_RESPONSE_PENDING = 0x61;

    /** Etiqueta que identifica si la respuesta tiene una longitud no valida. */
    private static final byte TAG_RESPONSE_INVALID_LENGTH = 0x6C;

    /** {@inheritDoc} */
	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		if(!isOpen()){
			throw new UnavailableReaderException("No existe dispositivo USB asignado a la conexion"); //$NON-NLS-1$
		}
		try {

			if(!this.ccidReader.isCardActive()){
				if(!this.ccidReader.isCardPresent()){
					//No hay tarjeta en el lector
					throw new CardNotPresentException();
				}
				//Hay tarjeta, pero no esta activa
				Log.i("es.gob.jmulticard", "La tarjeta del lector no esta activa, se reiniciara"); //$NON-NLS-1$ //$NON-NLS-2$
				this.reset();
			}

			if (DEBUG) {
				Log.d("es.gob.jmulticard", "APDU Enviada:\n" + HexUtils.hexify(command.getBytes(), true)); //$NON-NLS-1$ //$NON-NLS-2$
			}

			final ResponseApdu response;
			try {
				response = new ResponseApdu(this.ccidReader.transmit(command.getBytes()));

				if (DEBUG) {
					Log.d("es.gob.jmulticard", "APDU Recibida:\n" + HexUtils.hexify(response.getBytes(), true)); //$NON-NLS-1$ //$NON-NLS-2$
				}

		        // Solicitamos el resultado de la operacion si es necesario
		        if (response.getStatusWord().getMsb() == TAG_RESPONSE_PENDING) {

		            // Si ya se ha devuelto parte de los datos, los concatenamos al resultado
		            if (response.getData().length > 0) {
		                final byte[] data = response.getData();
		                final byte[] additionalData = transmit(
	                        new GetResponseApduCommand((byte) 0x00, response.getStatusWord().getLsb())
                        ).getBytes();

		                final byte[] fullResponse = new byte[data.length + additionalData.length];
		                System.arraycopy(data, 0, fullResponse, 0, data.length);
		                System.arraycopy(additionalData, 0, fullResponse, data.length, additionalData.length);

		                return new ResponseApdu(fullResponse);
		            }
		            return transmit(new GetResponseApduCommand((byte) 0x00, response.getStatusWord().getLsb()));
		        }

		        // En caso de longitud esperada incorrecta reenviamos la APDU con la longitud esperada.
		        // Incluimos la condicion del CLA igual 0x00 para que no afecte a las APDUs cifradas
		        // (de eso se encargara la clase de conexion con canal seguro)
		        else if (response.getStatusWord().getMsb() == TAG_RESPONSE_INVALID_LENGTH && command.getCla() == (byte) 0x00) {
		            command.setLe(response.getStatusWord().getLsb());
		            return transmit(command);
		        }

		        return response;
			}
			catch (final UsbDeviceException e) {
				//Ver por que motivo ha fallado la transmision
				throw new ApduConnectionException("Error enviando APDU: " + e, e); //$NON-NLS-1$
			}
		}
		catch(final NotAvailableUSBDeviceException e){
			//Error al acceder al dispositivo
			throw new UnavailableReaderException("No se puede acceder al dispositivo USB: " + e, e); //$NON-NLS-1$
		}
	}

	/** {@inheritDoc} */
	@Override
	public byte[] reset() throws ApduConnectionException {
		try {
			return this.ccidReader.resetCCID().getAtrBytes();
		}
		catch (final UsbDeviceException e) {
			throw new ApduConnectionException("Error al reiniciar tarjeta: " + e, e); //$NON-NLS-1$
		}
		catch (final NotAvailableUSBDeviceException e) {
			//Error al acceder al dispositivo
			throw new UnavailableReaderException("No se puede acceder al dispositivo USB: " + e, e); //$NON-NLS-1$
		}
	}

	/** {@inheritDoc} */
	@Override
	public void addCardConnectionListener(final CardConnectionListener ccl) {
		throw new UnsupportedOperationException("No soporta eventos de insercion o extraccion"); //$NON-NLS-1$
	}

	/** {@inheritDoc} */
	@Override
	public void removeCardConnectionListener(final CardConnectionListener ccl) {
		throw new UnsupportedOperationException("No soporta eventos de insercion o extraccion"); //$NON-NLS-1$
	}

	/** {@inheritDoc} */
	@Override
	public long[] getTerminals(final boolean onlyWithCardPresent) throws ApduConnectionException {
		if (onlyWithCardPresent) {
			try {
				if (!this.ccidReader.isCardPresent()) {
					return new long[0];
				}
			}
			catch (final NotAvailableUSBDeviceException e) {
				Log.e("es.gob.jmulticard", "No se ha podido determinar si hay tarjeta en el lector, se devolverra una lista vacia: " + e); //$NON-NLS-1$ //$NON-NLS-2$
				return new long[0];
			}
		}
		return new long[] { 0 };
	}

	/** {@inheritDoc} */
	@Override
	public String getTerminalInfo(final int terminal) throws ApduConnectionException {
		if (terminal != 0) {
			throw new IllegalArgumentException("Solo se accede al terminal 0, y se indico el " + terminal); //$NON-NLS-1$
		}
		return this.ccidReader.getDeviceName();
	}

	/** {@inheritDoc} */
	@Override
	public void setTerminal(final int t) {
		if (t != 0) {
			throw new IllegalArgumentException("Solo se accede al terminal 0, y se indico el " + t); //$NON-NLS-1$
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean isOpen() {
		return this.ccidReader.isOpen();
	}

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		// No hace nada
	}

}
