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

import java.util.HashMap;
import java.util.Map;

import es.inteco.labs.android.usb.device.ccid.instruction.Escape;
import es.inteco.labs.android.usb.device.ccid.instruction.GetParameters;
import es.inteco.labs.android.usb.device.ccid.instruction.GetSlotStatus;
import es.inteco.labs.android.usb.device.ccid.instruction.IccClock;
import es.inteco.labs.android.usb.device.ccid.instruction.IccPowerOff;
import es.inteco.labs.android.usb.device.ccid.instruction.IccPowerOn;
import es.inteco.labs.android.usb.device.ccid.instruction.ResetParameters;
import es.inteco.labs.android.usb.device.ccid.instruction.T0APDU;
import es.inteco.labs.android.usb.device.ccid.instruction.XfrBlock;
import es.inteco.labs.android.usb.device.ccid.response.UsbResponse;

/** Mapa de errores a comandos USB-CCID seg&uacute;n
 * <a href="www.usb.org/developers/devclass_docs/DWG_Smart-Card_CCID_Rev110.pdf">www.usb.org/developers/devclass_docs/DWG_Smart-Card_CCID_Rev110.pdf</a>.
 * @author Angel Gonzalez Villan */
public final class USBResponseErrorsMap {

    private final Map<USBResponseErrorStructure, String> errors;
    private static USBResponseErrorsMap map = null;

    /** Obtiene la lista de errores.
     * @return lista de errores */
    public static USBResponseErrorsMap getErrorsMap(){
        if (map == null){
            map = new USBResponseErrorsMap();
        }
        return map;
    }

    private USBResponseErrorsMap() {
        this.errors = new HashMap<USBResponseErrorStructure, String>();
        addPowerOnErrors();
        addPowerOffErrors();
        addGetSlotStatusErrors();
        addXfrBlockErrors();
        addGetParametersErrors();
        addResetParametersErrors();
        addEscapeErrors();
        addIccClockErrors();
        addT0APDUErrors();
    }

    private void addT0APDUErrors() {
        this.add(new USBResponseErrorStructure(T0APDU.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(T0APDU.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(T0APDU.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_PROCEDURE_BYTE_CONFLICT), "Protocol not managed"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(T0APDU.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_ABORTED), "Command aborted by control pipe"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(T0APDU.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
    }

    private void addIccClockErrors() {
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BUSY_WITH_AUTO_SEQUENCE), "Automatic sequence on-going"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_HW_ERROR), "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccClock.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
    }

    private void addEscapeErrors() {
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BUSY_WITH_AUTO_SEQUENCE), "Automatic sequence on-going"); //$NON-NLS-1$
        this.add(
                new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR, UsbResponse.ERROR_HW_ERROR),
                "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x07),
                "Protocol invalid or not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x10),
                "FI - DI pair invalid or not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x11),
                "Invalid TCCKTS parameter"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x12),
                "Guard time not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x13),
                "T=0 WI invalid or not supported  T=1 BWI or CWI invalid or not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x14),
                "Clock stop support requested invalid or not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x15),
                "IFSC size invalid or not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(Escape.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x16),
                "NAD value invalid or not supported"); //$NON-NLS-1$

    }

    private void addResetParametersErrors() {
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BUSY_WITH_AUTO_SEQUENCE), "Automatic sequence on-going"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_HW_ERROR), "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(ResetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
    }

    private void addGetParametersErrors() {
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BUSY_WITH_AUTO_SEQUENCE), "Automatic sequence on-going"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_HW_ERROR), "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetParameters.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
    }

    private void addXfrBlockErrors() {
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BUSY_WITH_AUTO_SEQUENCE), "Automatic sequence on-going"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_HW_ERROR), "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, (byte) 0x01, (byte) 0x00), "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, (byte) 0x01, UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, (byte) 0x01, UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, (byte) 0x01, UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "bPowerselect error (not supported)"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE,
                UsbResponse.ERROR_XFR_PARITY_ERROR), "parity error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE,
                UsbResponse.ERROR_XFR_OVERRUN), "Overrun"); //$NON-NLS-1$
        this.add(
                new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.ERROR_ICC_MUTE),
                "ICC mute (Time out)"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE, (byte) 0x08),
                "Bad wLevelParameter"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE, (byte) 0x01),
                "Bad dwLength"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(XfrBlock.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.ICC_STATUS_INACTIVE,
                UsbResponse.ERROR_CMD_ABORTED), "Command aborted by control pipe"); //$NON-NLS-1$
    }

    private void addGetSlotStatusErrors() {
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_HW_ERROR), "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(GetSlotStatus.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
    }

    private void addPowerOffErrors() {
        this.add(new USBResponseErrorStructure(IccPowerOff.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOff.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BUSY_WITH_AUTO_SEQUENCE), "Automatic sequence on-going"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOff.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOff.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOff.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOff.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
    }

    private void addPowerOnErrors() {
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x05),
                "bSlot does not exist"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "No ICC present"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_HW_ERROR), "Hardware error"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x07),
                "bPowerselect error (not supported)"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_XFR_PARITY_ERROR), "parity error on ATR"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_MUTE), "ICC mute (Time out)"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BAD_ATR_TS), "Bad TS in ATR"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_BAD_ATR_TCK), "Bad TCK in ATR"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_PROTOCOL_NOT_SUPPORTED), "Protocol not managed"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_ICC_CLASS_NOT_SUPPORTED), "ICC class not supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_ABORTED), "Command aborted by control pipe"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR, (byte) 0x00),
                "Command Not Supported"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_ACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_INACTIVE, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
        this.add(new USBResponseErrorStructure(IccPowerOn.ID_COMMAND, UsbResponse.ICC_STATUS_NOT_PRESENT, UsbResponse.COMMAND_STATUS_ERROR,
                UsbResponse.ERROR_CMD_SLOT_BUSY), "Busy"); //$NON-NLS-1$
    }

    private void add(final USBResponseErrorStructure structure, final String description) {
        this.errors.put(structure, description);
    }

    /** Obtiene la descripci&oacute;n de un error USB determinado.
     * @param structure Error USB
     * @return descripci&oacute;n del error */
    public String find(final USBResponseErrorStructure structure) {
        return this.errors.get(structure);
    }
}
