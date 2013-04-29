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
 * SIN NINGUNA GARANTIA; incluso sin la garanti­a implicita de comercializacion
 * o idoneidad para un proposito particular.
 */

package es.inteco.labs.android.usb;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import android.content.Context;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.UnavailableReaderException;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;
import es.inteco.labs.android.usb.device.SmartCardUsbDevice;
import es.inteco.labs.android.usb.device.SmartCardUsbFactory;
import es.inteco.labs.android.usb.device.exception.NotAvailableUSBDeviceException;
import es.inteco.labs.android.usb.device.exception.UsbDeviceException;

/** Conexi&oacute;n con lector de tarjetas inteligentes implementado sobre Android USB Host API.
 * Basado en <code>es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection</code>.
 * @author Jose Luis Escanciano Garcia */
public final class AndroidCCIDConnection implements ApduConnection{

	private List<SmartCardUsbDevice> terminals;
	private final Context androidContext;
	private int terminalID = -1;

	/** Construye una conexi&oacute;n con lector de tarjetas inteligentes implementado sobre Android USB Host API.
	 * @param ctx Contexto Android. */
	public AndroidCCIDConnection(final Context ctx){
		if (ctx == null) {
			throw new UnsupportedOperationException(
				"Debe facilitar un contexto Android valido a traves de PasswordCallbackManager.setDialogUIHandler()" //$NON-NLS-1$
			);
		}
		this.androidContext = ctx;
	}

	/** {@inheritDoc} */
	@Override
	public void open() throws ApduConnectionException {
		try {
			if(!isOpen()){
				this.terminals.get(this.terminalID).open();
			}
		}
		catch (final NotAvailableUSBDeviceException e) {
			//Error al acceder al dispositivo
			this.terminalID = -1;
			throw new UnavailableReaderException("No se puede acceder al dispositivo USB", e); //$NON-NLS-1$
		}
	}

	/** {@inheritDoc} */
	@Override
	public void close() throws ApduConnectionException {
		if(isOpen()) {
			this.terminals.get(this.terminalID).close();
		}
		try {
			this.terminals.get(this.terminalID).open();
		}
		catch (final NotAvailableUSBDeviceException e) {
			//Error al acceder al dispositivo
			this.terminalID = -1;
			throw new UnavailableReaderException("No se puede acceder al dispositivo USB", e); //$NON-NLS-1$
		}
	}

    /** Tag que identifica que es necesario recuperar el resultado del comando anterior. */
    private static final byte TAG_RESPONSE_PENDING = 0x61;

    /** Tag que identifica si la respuesta tiene una longitud no valida. */
    private static final byte TAG_RESPONSE_INVALID_LENGTH = 0x6C;

    /** {@inheritDoc} */
	@Override
	public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {
		if(!isOpen()){
			throw new UnavailableReaderException("No existe dispositivo USB asignado a la conexion"); //$NON-NLS-1$
		}
		try{
			if(!this.terminals.get(this.terminalID).isCardActive()){
				if(!this.terminals.get(this.terminalID).isCardPresent()){
					//No hay tarjeta en el lector
					throw new CardNotPresentException();
				}
				//Hay tarjeta, pero no esta activa
				CCIDUsbLogger.w("La SmartCard del lector no esta activa, se reiniciara"); //$NON-NLS-1$
				this.reset();
			}

			final ResponseApdu response;
			try {
				response = new ResponseApdu(this.terminals.get(this.terminalID).transmit(command.getBytes()));

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
			this.terminalID = -1;
			throw new UnavailableReaderException("No se puede acceder al dispositivo USB: " + e, e); //$NON-NLS-1$
		}
	}

	/** {@inheritDoc} */
	@Override
	public byte[] reset() throws ApduConnectionException {
		if(this.terminalID == -1){
			throw new UnavailableReaderException("No existe dispositivo USB asignado a la conexion"); //$NON-NLS-1$
		}
		try {
			return this.terminals.get(this.terminalID).resetCCID().getAtrBytes();
		}
		catch (final UsbDeviceException e) {
			throw new ApduConnectionException("Error al reiniciar tarjeta: " + e, e); //$NON-NLS-1$
		}
		catch (final NotAvailableUSBDeviceException e) {
			//Error al acceder al dispositivo
			this.terminalID = -1;
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
		this.terminals = new ArrayList<SmartCardUsbDevice>();
		Iterator<SmartCardUsbDevice> iteratorDevices = new ArrayList<SmartCardUsbDevice>().iterator();
		try {
			iteratorDevices = SmartCardUsbFactory.getInstance(this.androidContext).usbDevices().iterator();
		}
		catch (final InterruptedException e) {
			throw new ApduConnectionException("No es posible obtener la lista de lectores de tarjetas: " + e, e); //$NON-NLS-1$
		}
		while (iteratorDevices.hasNext()) {
			final SmartCardUsbDevice androidUsbSmartCard = iteratorDevices.next();
			if(androidUsbSmartCard.isCardReader()) {
				if(onlyWithCardPresent){
					try {
						if(androidUsbSmartCard.isCardPresent()){
							this.terminals.add(androidUsbSmartCard);
						}
					}
					catch (final NotAvailableUSBDeviceException e) {
						//Problema al acceder al dispositivo => no se anade
						CCIDUsbLogger.w(e);
					}
				}
				else {
					this.terminals.add(androidUsbSmartCard);
				}
			}
		}

		final long[] tmp = new long[this.terminals.size()];
		for (int i = 0; i < this.terminals.size(); i++) {
			tmp[i] = i;
		}
		return tmp;
	}

	/** {@inheritDoc} */
	@Override
	public String getTerminalInfo(final int terminal) throws ApduConnectionException {
		return this.terminals.get(terminal).getDeviceName();
	}

	/** {@inheritDoc} */
	@Override
	public void setTerminal(final int t) {
		this.terminalID = t;
	}

	/** {@inheritDoc} */
	@Override
	public boolean isOpen() {
		return this.terminalID != -1 ? this.terminals.get(this.terminalID).isOpen() : false;
	}

}
