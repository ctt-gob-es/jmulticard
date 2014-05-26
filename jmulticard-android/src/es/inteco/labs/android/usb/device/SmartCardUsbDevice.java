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

package es.inteco.labs.android.usb.device;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.SystemClock;
import android.util.Log;
import es.gob.jmulticard.HexUtils;
import es.inteco.labs.android.usb.device.ccid.instruction.UsbCommand;
import es.inteco.labs.android.usb.device.ccid.instruction.UsbInstructionFactory;
import es.inteco.labs.android.usb.device.ccid.response.UsbResponse;
import es.inteco.labs.android.usb.device.data.ATR;
import es.inteco.labs.android.usb.device.exception.NotAvailableUSBDeviceException;
import es.inteco.labs.android.usb.device.exception.UsbCommandTransmissionException;
import es.inteco.labs.android.usb.device.exception.UsbDeviceException;
import es.inteco.labs.android.usb.device.exception.UsbResponseException;
import es.inteco.labs.android.usb.device.exception.UsbSmartCardChannelException;

/** Dispositivo USB SmartCard CCID conectado.
 * @author Jose Luis Escanciano Garcia */
public final class SmartCardUsbDevice extends AnyUSBDevice{

	private static final int MAX_TRANSMIT_RETRIES = 3;
	private static final int MAX_RECONNECT_CHANNEL_RETRIES = 3;
	private static final int RETRY_TIMEOUT = 1000;

	private SmartCardChannel channel;
	private int flag_transmit_retries = 0;
	private int flag_reconnect_channel = 0;

	/** Constructor.
	 * @param usbDev Lector de tarjetas USB CCID.
	 * @param usbManager Gestor de dispositivos USB de Android
	 * @throws UsbDeviceException */
	public SmartCardUsbDevice(final UsbManager usbManager, final UsbDevice usbDev) throws UsbDeviceException {
		super(usbManager, usbDev);
	}

	/** Indica si la tarjeta est&aacute; presente en el lector de tarjetas.
	 * @return <code>true</code> si la tarjeta est&aacute; presente en el lector de tarjetas,
	 *         <code>false</code> en caso contrario
	 * @throws NotAvailableUSBDeviceException */
	public boolean isCardPresent() throws NotAvailableUSBDeviceException{
		try {
			final UsbResponse response = getSlotStatus();
			return isCardPresent(response);
		}
		catch (final UsbCommandTransmissionException e) {
			this.close();
			this.channel = this.open();
			Log.w("es.gob.afirma", "Error de transmision USB: " + e);  //$NON-NLS-1$//$NON-NLS-2$
			return false;
		}
		catch (final UsbDeviceException e) {
			Log.w("es.gob.afirma", "Error en dispositivo USB: " + e);  //$NON-NLS-1$//$NON-NLS-2$
			return false;
		}
		catch (final UsbSmartCardChannelException e) {
			// Es necesario reconectar
			releaseChannel();
			return false;
		}
	}

	/** Indica si la tarjeta est&aacute; presente y activa en el lector de tarjetas
	 * @return <code>true</code> si la tarjeta est&aacute; presente y activa en el lector de tarjetas,
	 *         <code>false</code> en caso contrario
	 * @throws NotAvailableUSBDeviceException
	 */
	public boolean isCardActive() throws NotAvailableUSBDeviceException{
		try {
			final UsbResponse response = getSlotStatus();
			return isCardPresent(response) && isCardActive(response);
		}
		catch (final UsbCommandTransmissionException e) {
			this.close();
			this.channel = this.open();
			Log.w("es.gob.afirma", "Error de transmision USB: " + e);  //$NON-NLS-1$//$NON-NLS-2$
			return false;
		}
		catch (final UsbDeviceException e) {
			Log.w("es.gob.afirma", "Error en dispositivo USB: " + e);  //$NON-NLS-1$//$NON-NLS-2$
			return false;
		}
		catch (final UsbSmartCardChannelException e) {
			// Es necesario reconectar
			releaseChannel();
			return false;
		}
	}

	/** Indica si la tarjeta est&aacute; presente en el lector de tarjetas
	 * @param slotStatus Respuesta USB a una peticion getSlotStatus
	 * @return <code>true</code> si la tarjeta est&aacute; presente en el lector de tarjetas,
	 *         <code>false</code> en caso contrario */
	private static boolean isCardPresent(final UsbResponse slotStatus){
		return slotStatus != null && slotStatus.getIccStatus() != UsbResponse.ICC_STATUS_NOT_PRESENT ? true : false;
	}

	/** Indica si la tarjeta est&aacute; presente y activa en el lector de tarjetas
	 * @param slotStatus Respuesta USB a una peticion getSlotStatus
	 * @return <code>true</code> si la tarjeta est&aacute; presente y activa en el lector de tarjetas,
	           <code>false</code> en caso contrario */
	private static boolean isCardActive(final UsbResponse slotStatus){
		return slotStatus != null && slotStatus.getIccStatus() == UsbResponse.ICC_STATUS_ACTIVE ? true : false;
	}

	/** Env&iacute;a una petici&oacute;n <i>getSlotStatus</i> al lector.
	 * @return
	 * @throws UsbDeviceException
	 * @throws UsbCommandTransmissionException
	 * @throws UsbSmartCardChannelException
	 * @throws NotAvailableUSBDeviceException
	 */
	protected UsbResponse getSlotStatus() throws UsbDeviceException, UsbCommandTransmissionException, UsbSmartCardChannelException, NotAvailableUSBDeviceException{
		final UsbCommand getStatus = UsbInstructionFactory.getInstance().getSlotStatusCommand();
		return getChannel().transmit(getStatus);
	}

	/** Manda un reset al dispositivo CCID.
	 * @return ATR devuelto por el dispositivo
	 * @throws UsbDeviceException
	 * @throws NotAvailableUSBDeviceException */
	public ATR resetCCID() throws UsbDeviceException, NotAvailableUSBDeviceException{
		if(!isCardPresent()){
			throw new UsbDeviceException("No se ha detectado una tarjeta en el lector"); //$NON-NLS-1$
		}
		try {
			//PowerOff
			final UsbCommand powerOffCommand = UsbInstructionFactory.getInstance().getIccPowerOffCommand();
			final UsbResponse powerOffResponse = getChannel().transmit(powerOffCommand);
			if(!powerOffResponse.isOk()){
				throw new UsbDeviceException("Imposible enviar PowerOff al terminal [" + HexUtils.hexify(new byte[]{powerOffResponse.getStatus()}, false) + "] - (" + HexUtils.hexify(new byte[]{powerOffResponse.getError()}, false) + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			}
			//PowerOn
			final UsbCommand powerOnCommand = UsbInstructionFactory.getInstance().getIccPowerOnCommand();
			final UsbResponse powerOnResponse = getChannel().transmit(powerOnCommand);
			if(powerOnResponse.isOk()){
				return new ATR(powerOnResponse.getDataBytes());
			}
			throw new UsbDeviceException("Imposible enviar PowerOn al terminal"); //$NON-NLS-1$
		}
		catch (final UsbCommandTransmissionException e) {
			throw new UsbDeviceException(e);
		}
		catch (final UsbResponseException e){
			throw new UsbDeviceException(e);
		}
		catch (final UsbSmartCardChannelException e) {
			// Es necesario reconectar
			if(this.flag_reconnect_channel++ < MAX_RECONNECT_CHANNEL_RETRIES) {
				releaseChannel();
				return resetCCID();
			}
			throw new UsbDeviceException(e);
		}
	}

	/** Env&iacute;a una APDU al dispositivo.
	 * @param apdu Comando APDU
	 * @return Respuesta al env&iacute;o (APDU respuesta)
	 * @throws UsbDeviceException
	 * @throws NotAvailableUSBDeviceException */
	public byte[] transmit(final byte[] apdu) throws UsbDeviceException, NotAvailableUSBDeviceException{
		try{
			final UsbCommand xfrBlock = UsbInstructionFactory.getInstance().getXfrBlockCommand(apdu);
			final UsbResponse response = getChannel().transmit(xfrBlock);
			if(response.isOk()){
				this.flag_transmit_retries = 0;
				this.flag_reconnect_channel = 0;
				return response.getDataBytes();
			}
			throw new UsbDeviceException("Error en la transmision de la APDU"); //$NON-NLS-1$
		}
		catch (final UsbCommandTransmissionException e) {
			// Es necesario reconectar
			if(this.flag_transmit_retries++ < MAX_TRANSMIT_RETRIES) {
				SystemClock.sleep(RETRY_TIMEOUT);
				return transmit(apdu);
			}
			throw new UsbDeviceException(e);
		}
		catch (final UsbResponseException e) {
			throw new UsbDeviceException(e);
		}
		catch (final UsbSmartCardChannelException e) {
			if(this.flag_reconnect_channel++ < MAX_RECONNECT_CHANNEL_RETRIES) {
				releaseChannel();
				return transmit(apdu);
			}
			throw new UsbDeviceException(e);
		}
	}

	/** Indica si se ha abierto el canal con el dispositivo
	 * @return <code>true</code> si se ha abierto el canal con el dispositivo, <code>false</code>
	 *         en caso contrario */
	public boolean isOpen(){
		return this.channel != null;
	}

	/** Abre la conexi&oacute;n con un dispositivo SmartCard.
	 * @return Conexi&oacute;n con un dispositivo SmartCard
	 * @throws NotAvailableUSBDeviceException */
	public SmartCardChannel open() throws NotAvailableUSBDeviceException {
		try {
			return this.getChannel();
		}
		catch (final UsbDeviceException e) {
			throw new NotAvailableUSBDeviceException("Error en la apertura del canal: " + e, e); //$NON-NLS-1$
		}
	}

	/** Cierra la conexi&oacute;n con un dispositivo SmartCard.
	 * @return <code>true</code> si el dispositivo qued&oacute; cerrado tras la llamada, <code>false</code>
	 *         en caso contrario */
	public boolean close() {
		if(this.isOpen()){
			return this.releaseChannel();
		}
		return true;
	}

	/** Solicita el canal de comunicaci&oacute;n a trav&eacute;s del interfaz (0) del dispositivo
	 * @return Canal de comunicaci&oacute;n USB
	 * @throws UsbDeviceException
	 * @throws NotAvailableUSBDeviceException */
	private SmartCardChannel getChannel() throws UsbDeviceException, NotAvailableUSBDeviceException{
		if(this.channel != null){
			return this.channel;
		}
		if(getUsbInterface() != null){
			if (!getUsbDeviceConnection().claimInterface(getUsbInterface(), true)) {
				throw new NotAvailableUSBDeviceException("Imposible acceder al interfaz del dispositivo USB"); //$NON-NLS-1$
			}
			this.channel = new SmartCardChannel(getUsbDeviceConnection(), getUsbInterface());
			return this.channel;
		}
		throw new UsbDeviceException("usbInterface cannot be NULL"); //$NON-NLS-1$
	}

	/** Libera el canal de comunicaci&oacute;n establecido a trav&eacute;s del interfaz (0) del dispositivo. */
	private boolean releaseChannel(){
		if(this.channel != null){
			this.channel = null;
			return getUsbDeviceConnection().releaseInterface(getUsbInterface());
		}
		return true;
	}
}
