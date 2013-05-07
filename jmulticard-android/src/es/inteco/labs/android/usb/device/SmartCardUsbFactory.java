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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import android.content.Context;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import es.inteco.labs.android.usb.CCIDUsbLogger;
import es.inteco.labs.android.usb.device.exception.UsbDeviceException;

/** Factor&iacute;a de lectores de tarjetas (Android USB Host API).
 * @author Jose Luis Escanciano Garcia
 * @author Angel Gonzalez Villan */
public class SmartCardUsbFactory {

	/** Singleton. */
	private static SmartCardUsbFactory instance = null;

	private final Context appContext;
	private final UsbManager usbManager;

	protected static final String ACTION_USB_PERMISSION = "es.inteco.labs.dnie.android.USB"; //$NON-NLS-1$

	/** Constructor privado. */
	private SmartCardUsbFactory(final Context context){
		super();
		this.appContext = context;
		this.usbManager = (UsbManager) this.appContext.getSystemService(Context.USB_SERVICE);
	}

	/** Obtiene la instancia (<i>singleton</i>) de la factor&iacute;a.
	 * @param context Contexto de aplicaci&oacute;n Android
	 * @return factor&iacute;a de lectores de tarjetas */
	public static SmartCardUsbFactory getInstance(final Context context){
		if(instance == null || !context.equals(instance.appContext)){
			instance = new SmartCardUsbFactory(context);
		}
		return instance;
	}

	/** Busca la lista de terminales conectados.
	 * @return Terminales USB conectados
	 * @throws InterruptedException */
	public List<SmartCardUsbDevice> usbDevices() throws InterruptedException{
		final List<SmartCardUsbDevice> androidUsbDevices = new ArrayList<SmartCardUsbDevice>();
		final HashMap<String, UsbDevice> usbDeviceList = this.usbManager.getDeviceList();
		final Iterator<UsbDevice> usbDevicesIterator = usbDeviceList.values().iterator();
		while(usbDevicesIterator.hasNext()){
			final UsbDevice usbDevice = usbDevicesIterator.next();
			if(this.usbManager.hasPermission(usbDevice)){
				try {
					androidUsbDevices.add(new SmartCardUsbDevice(this.usbManager, usbDevice));
				}
				catch (final UsbDeviceException e) {
					CCIDUsbLogger.e(e);
				}
			}
		}
		return androidUsbDevices;
	}
}
