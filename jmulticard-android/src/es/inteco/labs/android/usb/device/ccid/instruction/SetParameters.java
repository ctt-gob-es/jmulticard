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

package es.inteco.labs.android.usb.device.ccid.instruction;

import java.nio.ByteBuffer;

import es.gob.jmulticard.HexUtils;

/** Comando USB <i>SetParameters</i>.
 * @author Jose Luis Escanciano Garcia */
final class SetParameters extends UsbCommand {

	/** ID de comando USB. */
	public static final int ID_COMMAND = 6;

	private static final byte PARAMETER_T0 = (byte) 0x00;

	SetParameters(final byte insCount, final byte[] parameters){
		this.instructionCount = insCount;
		final ByteBuffer commandBuffer = ByteBuffer.allocate(UsbCommand.USB_HEADER_BASE_SIZE + parameters.length);
		commandBuffer.put((byte) 0x61);
		HexUtils.intToByteArray(parameters.length);
		commandBuffer.put(new byte[]{(byte) 0x00, insCount, PARAMETER_T0, (byte) 0x00, (byte) 0x00});
		commandBuffer.put(parameters);
		this.command = commandBuffer.array();
	}

	@Override
	public int getCommandID() {
		return ID_COMMAND;
	}

}
