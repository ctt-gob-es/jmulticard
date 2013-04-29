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

package es.inteco.labs.android.usb.device.ccid.response;

import java.math.BigInteger;

import es.gob.jmulticard.HexUtils;
import es.inteco.labs.android.usb.device.USBResponseErrorStructure;
import es.inteco.labs.android.usb.device.USBResponseErrorsMap;
import es.inteco.labs.android.usb.device.ccid.instruction.UsbCommand;
import es.inteco.labs.android.usb.device.exception.UsbResponseException;

/** Respuesta a comandos USB.
 * @author Jose Luis Escanciano Garcia
 * @author Angel Gonzalez Villan */
public final class UsbResponse {

	/** Tama&ntilde;o de la cabecera de respuesta. */
	public static final int USB_HEADER_BASE_SIZE = 10;

	//SLOT Status: ICC Status + Command Status

	/** ICC_STATUS_ACTIVE. */
	public static final byte ICC_STATUS_ACTIVE = (byte) 0x00;

	/** ICC_STATUS_INACTIVE. */
	public static final byte ICC_STATUS_INACTIVE = (byte) 0x01;

	/** ICC_STATUS_NOT_PRESENT. */
	public static final byte ICC_STATUS_NOT_PRESENT = (byte) 0x02;

	/** COMMAND_STATUS_OK. */
	public static final byte COMMAND_STATUS_OK = (byte) 0x00;

	/** COMMAND_STATUS_ERROR. */
	public static final byte COMMAND_STATUS_ERROR = (byte) 0x01;

	/** COMMAND_STATUS_TIME_EXTENSION. */
	public static final byte COMMAND_STATUS_TIME_EXTENSION = (byte) 0x02;

	//Tipos de Error

	/** ERROR_CMD_ABORTED. */
	public static final byte ERROR_CMD_ABORTED = (byte) 0xFF;

	/** ERROR_ICC_MUTE. */
	public static final byte ERROR_ICC_MUTE = (byte) 0xFE;

	/** ERROR_XFR_PARITY_ERROR. */
	public static final byte ERROR_XFR_PARITY_ERROR = (byte) 0xFD;

	/** ERROR_XFR_OVERRUN. */
	public static final byte ERROR_XFR_OVERRUN = (byte) 0xFC;

	/** ERROR_HW_ERROR. */
	public static final byte ERROR_HW_ERROR = (byte) 0xFB;

	/** ERROR_BAD_ATR_TS. */
	public static final byte ERROR_BAD_ATR_TS = (byte) 0xF8;

	/** ERROR_BAD_ATR_TCK. */
	public static final byte ERROR_BAD_ATR_TCK = (byte) 0xF7;

	/** ERROR_ICC_PROTOCOL_NOT_SUPPORTED. */
	public static final byte ERROR_ICC_PROTOCOL_NOT_SUPPORTED = (byte) 0xF6;

	/** ERROR_ICC_CLASS_NOT_SUPPORTED. */
	public static final byte ERROR_ICC_CLASS_NOT_SUPPORTED = (byte) 0xF5;

	/** ERROR_PROCEDURE_BYTE_CONFLICT. */
	public static final byte ERROR_PROCEDURE_BYTE_CONFLICT = (byte) 0xF4;

	/** ERROR_BUSY_WITH_AUTO_SEQUENCE. */
	public static final byte ERROR_BUSY_WITH_AUTO_SEQUENCE = (byte) 0xF2;

	/** ERROR_CMD_SLOT_BUSY. */
	public static final byte ERROR_CMD_SLOT_BUSY = (byte) 0xE0;

	private final byte[] responseBytes;
	private final UsbCommand command;
	private byte iccStatus;
	private byte commandStatus;

	/** Construye una respuesta a un comando USB.
	 * @param usbCommand Comando USB.
	 * @param response Respuesta */
	public UsbResponse(final UsbCommand usbCommand, final byte[] response){
		super();
		final byte[] length = new byte[]{(byte)0x00, response[4], response[3], response[2], response[1]};
		final int absoluteDataLength = new BigInteger(length).intValue();
		this.responseBytes = HexUtils.subArray(response, 0, USB_HEADER_BASE_SIZE + absoluteDataLength);
		this.command = usbCommand;
		processStatus();
	}

	/** Devuelve los octetos de la respuesta.
	 * @return Octetos de la respuesta */
	protected byte[] getBytes(){
		return this.responseBytes;
	}

	/** Devuelve los bytes de la cabecera USB de la respuesta. */
	protected byte[] getHeaderBytes(){
		return HexUtils.subArray(this.responseBytes, 0, USB_HEADER_BASE_SIZE);
	}

	/** Devuelve los octetos de los datos de la respuesta.
	 * @return Octetos de los datos de la respuesta
	 * @throws UsbResponseException */
	public byte[] getDataBytes() throws UsbResponseException{
		this.processStatusErrors(this.command);
		return HexUtils.subArray(this.responseBytes, USB_HEADER_BASE_SIZE, this.responseBytes.length - USB_HEADER_BASE_SIZE);
	}

	/** Devuelve el byte que indica el tipo de respuesta. */
	protected byte getMessageType(){
		return this.responseBytes[0];
	}

	/** Devuelve el n&uacute;mero secuencial de la respuesta. Debe coincidir con el hom&oacute;logo de la petici&oacute;n.
	 * @return N&uacute;mero secuencial de la respuesta */
	public int getSequenceNumber(){
		return this.responseBytes[6];
	}

	/** Devuelve el octeto asociado al estado del z&oacute;calo (<i>slot</i>).
	 * @return Octeto asociado al estado del z&oacute;calo (<i>slot</i>) */
	public byte getStatus(){
		return this.responseBytes[7];
	}

	/** Devuelve el octeto asociado al error del z&oacute;calo (<i>slot</i>).
	 * @return Octeto asociado al error del z&oacute;calo (<i>slot</i>) */
	public byte getError(){
		return this.responseBytes[8];
	}

	/** Devuelve el par&aacute;metro extra de la respuesta. Su significado depende del tipo de respuesta.
	 * @return Par&aacute;metro extra de la respuesta */
	protected byte getExtraParameter(){
		return this.responseBytes[9];
	}

	/** Devuelve el estado del ICC (se procesa a partir del estado del z&oacute;calo).
	 * @return Estado del ICC */
	public byte getIccStatus(){
		return this.iccStatus;
	}

	/** Devuelve el estado del comando (se procesa a partir del estado del z&oacute;calo)
	 * @return Estado del comando */
	public byte getCommandStatus(){
		return this.commandStatus;
	}

	/** Indica si la respuesta no presenta errores.
	 * @return <code>true</code> si la respuesta no presenta errores, <code>false</code> en caso contrario */
	public boolean isOk(){
		return COMMAND_STATUS_OK == this.commandStatus;
	}

	/** Procesa el ICC Status y Command Status a partir del byte de SlotStatus. */
	private void processStatus(){
		final byte bStatus = this.getStatus();
		this.iccStatus = (byte)(bStatus & 0x03);
		this.commandStatus = (byte)(bStatus >> 6 & 0x03 );
	}

	/** Procesa errores en base a ICC Status, Command Status y Error.
	 * @param cmd Comando que origin&oacute; la respuesta
	 * @throws UsbResponseException En caso de detectarse alg&uacute; error en la respuesta */
	protected void processStatusErrors(final UsbCommand cmd) throws UsbResponseException{
		final USBResponseErrorsMap errorsMap = USBResponseErrorsMap.getErrorsMap();
	    final byte error = getError();
	  	//A continuacion se procesan los campos de error
	    final USBResponseErrorStructure structure = new USBResponseErrorStructure(cmd.getCommandID(), getIccStatus(), getCommandStatus(), error);
	    final String errorDescription = errorsMap.find(structure);
	    if (errorDescription != null){
	    	throw new UsbResponseException(error, getIccStatus(), getCommandStatus(), errorDescription);
	    }
	}

	@Override
	public String toString() {
		return HexUtils.hexify(this.responseBytes, false);
	}
}
