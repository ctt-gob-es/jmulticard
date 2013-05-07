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

/** Esta clase encapsula todos los par&aacute;metros que configuran un error en el env&iacute;o de un comando USB.
 * @author Angel Gonzalez Villan */
public class USBResponseErrorStructure {

	private int requestID;
	private byte iccStatus;
	private byte commandStatus;
	private byte bError;

	/** Construye una clase que representa un error USB.
	 * @param requestID Identificador de petici&oacute;n
	 * @param iccStatus Estado del lector
	 * @param commandStatus Estado del Comando
	 * @param bError C&oacute;digo de error */
	public USBResponseErrorStructure(final int requestID,
			                  final byte iccStatus,
			                  final byte commandStatus,
			                  final byte bError) {
		super();
		this.requestID = requestID;
		this.iccStatus = iccStatus;
		this.commandStatus = commandStatus;
		this.bError = bError;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + this.bError;
		result = prime * result + this.commandStatus;
		result = prime * result + this.iccStatus;
		result = prime * result + this.requestID;
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final USBResponseErrorStructure other = (USBResponseErrorStructure) obj;
		if (this.bError != other.bError) {
			return false;
		}
		if (this.commandStatus != other.commandStatus) {
			return false;
		}
		if (this.iccStatus != other.iccStatus) {
			return false;
		}
		if (this.requestID != other.requestID) {
			return false;
		}
		return true;
	}

	byte getIccStatus() {
		return this.iccStatus;
	}

	void setIccStatus(final byte iccStatus) {
		this.iccStatus = iccStatus;
	}

	byte getCommandStatus() {
		return this.commandStatus;
	}

	void setCommandStatus(final byte commandStatus) {
		this.commandStatus = commandStatus;
	}

	byte getbError() {
		return this.bError;
	}

	void setbError(final byte bError) {
		this.bError = bError;
	}

	int getRequestID() {
		return this.requestID;
	}

	void setRequestID(final int requestID) {
		this.requestID = requestID;
	}

}
