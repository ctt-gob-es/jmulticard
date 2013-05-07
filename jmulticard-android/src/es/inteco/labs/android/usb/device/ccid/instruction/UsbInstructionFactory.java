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

/** Factor&iacute;a de comandos USB.
 * @author Jose Luis Escanciano Garcia */
public final class UsbInstructionFactory {
	private static UsbInstructionFactory instance = null;
	private byte instructionCount;

	/** Constructor. */
	private UsbInstructionFactory() {
		super();
		this.instructionCount = (byte) 0x00;
	}

	/** Devuelve la instancia <i>singleton</i> de la factor&iacute;a de comandos USB.
	 * @return Instancia <i>singleton</i> de la factor&iacute;a de comandos USB */
	public static UsbInstructionFactory getInstance(){
		if(instance == null){
			instance = new UsbInstructionFactory();
		}
		return instance;
	}

	/** Obtiene un comando de tipo <i>SlotStatus</i>.
	 * @return Comando de tipo <i>SlotStatus</i> */
	public UsbCommand getSlotStatusCommand(){
		return new GetSlotStatus(this.instructionCount++);
	}

	/** Obtiene un comando de tipo <i>IccPowerOff</i>.
	 * @return Comando de tipo <i>IccPowerOff</i> */
	public UsbCommand getIccPowerOnCommand(){
		return new IccPowerOn(this.instructionCount++);
	}

	/** Obtiene un comando de tipo <i>IccPowerOff</i>.
	 * @return Comando de tipo <i>IccPowerOff</i> */
	public UsbCommand getIccPowerOffCommand(){
		return new IccPowerOff(this.instructionCount++);
	}

	/** Obtiene un comando de tipo <i>XfrBlock</i> que encapsula una APDU completa.
	 * @param apdu APDU que se encapsular&aacute; en este comando USB
	 * @return Comando de tipo <i>XfrBlock</i> */
	public UsbCommand getXfrBlockCommand(final byte[] apdu){
		return new XfrBlock(this.instructionCount++, apdu, XfrBlock.APDU_BEGIN_AND_END);
	}

	/** Obtiene un comando de tipo <i>XfrBlock</i> que encapsula una APDU completa.
	 * @param apdu APDU que se encapsular&aacute; en este comando USB
	 * @param type Tipo
	 * @return Comando de tipo <i>XfrBlock</i> */
	public UsbCommand getXfrBlockCommand(final byte[] apdu, final byte[] type){
		return new XfrBlock(this.instructionCount++, apdu, type);
	}

	/** Obtiene un comando de tipo <i>T0ApduCommand</i>.
	 * @return Comando de tipo <i>T0ApduCommand</i> */
	public UsbCommand getT0ApduCommand(){
		return new T0APDU(this.instructionCount++);
	}

	/** Obtiene un comando de tipo <i>GetParameters</i>.
	 * @return Comando de tipo <i>GetParameters</i> */
	public UsbCommand getParametersCommand(){
		return new GetParameters(this.instructionCount++);
	}

	/** Obtiene un comando de tipo <i>GetParameters</i>.
	 * @param parameters Par&aacute;metros
	 * @return Comando de tipo <i>GetParameters</i> */
	public UsbCommand getSetParametersCommand(final byte[] parameters){
		return new SetParameters(this.instructionCount++, parameters);
	}
}
