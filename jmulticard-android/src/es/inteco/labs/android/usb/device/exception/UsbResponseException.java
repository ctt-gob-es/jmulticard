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

package es.inteco.labs.android.usb.device.exception;

import es.gob.jmulticard.HexUtils;

/** Error en la respuesta de un comando USB.
 * @author Jose Luis Escanciano */
public class UsbResponseException extends Exception {

	private static final long serialVersionUID = 6173469040352723982L;

	private final byte errorCode, iccStatus, commandStatus;

	/** Crea una excepci&oacute;n de error en la respuesta de un comando USB.
	 * @param bError C&oacute;digo de error
	 * @param iccStatus Estado del ICC
	 * @param commandStatus Estado del comando
	 * @param msg Mensaje de la excepci&oacute;n */
	public UsbResponseException(final byte bError, final byte iccStatus, final byte commandStatus, final String msg) {
		super(msg);
		this.errorCode = bError;
		this.iccStatus = iccStatus;
		this.commandStatus = commandStatus;
	}

	@Override
	public String toString() {
		return "Respuesta de error USB [codigo=" + //$NON-NLS-1$
		       HexUtils.hexify(new byte[] { this.errorCode }, false) +
		       ";estado del ICC=" + //$NON-NLS-1$
		       HexUtils.hexify(new byte[] { this.iccStatus }, false) +
		       ";estado del comando=" + //$NON-NLS-1$
		       HexUtils.hexify(new byte[] { this.commandStatus }, false) +
		       "]: " + this.getMessage(); //$NON-NLS-1$
	}

}
