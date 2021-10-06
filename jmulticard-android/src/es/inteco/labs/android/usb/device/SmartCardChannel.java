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

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.os.SystemClock;
import es.gob.jmulticard.HexUtils;
import es.inteco.labs.android.usb.device.ccid.instruction.UsbCommand;
import es.inteco.labs.android.usb.device.ccid.response.UsbResponse;
import es.inteco.labs.android.usb.device.exception.UsbCommandTransmissionException;
import es.inteco.labs.android.usb.device.exception.UsbSmartCardChannelException;

/** Representa el canal a traves del cual se procesan las peticiones USB para un dispositivo concreto.
 * @author Jose Luis Escanciano Garcia */
final class SmartCardChannel {
	private UsbEndpoint endPointIn;
	private UsbEndpoint endPointOut;

	private final UsbDeviceConnection usbDeviceConnection;

	private static final int MAX_SIZE_APDU_T0 = 260;
	private static final int MAX_TIME_EXTENSION_RETRIES = 16;
	private static final int TIME_EXTENSION_RETRY_MS = 200;
	private static final int TIMEOUT_MS = 5000;

	/** Constructor. Inicia los EndPoints del Interfaz del dispositivo
	 * @param usbDevCon
	 * @param usbInterface */
	protected SmartCardChannel(final UsbDeviceConnection usbDevCon, final UsbInterface usbInterface) {
		this.usbDeviceConnection = usbDevCon;
		for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
			final UsbEndpoint usbEndPoint = usbInterface.getEndpoint(i);
			if (usbEndPoint.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
				if (usbEndPoint.getDirection() == UsbConstants.USB_DIR_IN) {
					this.endPointIn = usbEndPoint;
				}
				else if (usbEndPoint.getDirection() == UsbConstants.USB_DIR_OUT) {
					this.endPointOut = usbEndPoint;
				}
			}
		}
	}

	/** Transmite un comando USB a trav&eacute;s del interfaz del dispositivo.
	 * @param command Comando USB
	 * @return Respuesta USB al comando
	 * @throws UsbCommandTransmissionException
	 * @throws UsbSmartCardChannelException */
	UsbResponse transmit(final UsbCommand command) throws UsbCommandTransmissionException, UsbSmartCardChannelException{

		final int responseLength = MAX_SIZE_APDU_T0 + UsbResponse.USB_HEADER_BASE_SIZE;

		//Se envia el comando
		usbSendCommand(command.getBytes());

		//Se recoge la respuesta
		UsbResponse usbResponse = new UsbResponse(command, usbRetrieveResponse(responseLength));

		//Si el dispositivo CCID solicita Time Extension hay que esperar a obtener la respuesta nueva Request Wait
		int timeExtensionRetryCounter = 0;
		while(usbResponse.getCommandStatus() == UsbResponse.COMMAND_STATUS_TIME_EXTENSION && timeExtensionRetryCounter++ < MAX_TIME_EXTENSION_RETRIES){
			//Se esperan TIME_EXTENSION_RETRY_MS ms antes de solicitar de nuevo la respuesta
			SystemClock.sleep(TIME_EXTENSION_RETRY_MS);
			usbResponse = new UsbResponse(command, usbRetrieveResponse(responseLength));
		}

	    //Comprobar si la respuesta corresponde con la peticion
	    if(command.getInstructionCount() != usbResponse.getSequenceNumber()){
	    	//TODO: Si esto pasa, lo mejor es reiniciar la conexion con el dispositivo
	    	throw new UsbSmartCardChannelException("El ID de secuencia del comando [" + command.getInstructionCount() + "] no coincide con el de la respuesta [" + usbResponse.getSequenceNumber() + "]"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	    }

		return usbResponse;
	}

	/** Env&iacute;a un comando USB a trav&eacute;s del Endpoint OUT.
	 * @param data Comando a enviar
	 * @throws UsbCommandTransmissionException */
	private void usbSendCommand(final byte[] data) throws UsbCommandTransmissionException {
		final int dataTransferred = this.usbDeviceConnection.bulkTransfer(this.endPointOut, data, data.length, TIMEOUT_MS);
		if(!(dataTransferred == 0 || dataTransferred==data.length)) {
			throw new UsbCommandTransmissionException("Error al transmitir el comando [" + dataTransferred + " ; " + data.length + "]"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		}
	}

	/** Recoge la respuesta de un comando USB a trav&eacute;s del Endpoint IN
	 * @param responseSize Tama&ntilde;o de respuesta esperado
	 * @return Respuesta al comando USB
	 * @throws UsbCommandTransmissionException */
	private byte[] usbRetrieveResponse(final int responseSize) throws UsbCommandTransmissionException{
		final byte[] responseBuffer = new byte[responseSize];
		final int dataTransferred = this.usbDeviceConnection.bulkTransfer(this.endPointIn, responseBuffer, responseBuffer.length, TIMEOUT_MS);
		if(dataTransferred >= 0){
			return HexUtils.subArray(responseBuffer, 0, dataTransferred);
		}
		throw new UsbCommandTransmissionException("Error al recibir respuesta del comando [" + dataTransferred + "]"); //$NON-NLS-1$ //$NON-NLS-2$
	}

}
