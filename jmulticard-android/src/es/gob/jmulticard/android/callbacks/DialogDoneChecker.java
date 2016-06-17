/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * Date: 11/01/11
 * You may contact the copyright holder at: soporte.afirma5@mpt.es
 */

package es.gob.jmulticard.android.callbacks;


/**
 * Clase para instanciar un objeto mutable y crear una sincronizaci&oacute;n durante las llamadas a di&aacute;logo mediante callbacks
 */
public class DialogDoneChecker {
    boolean canReady = false;
    boolean pinReady = false;

    public DialogDoneChecker() {

    }

    public void setCanReady(final boolean cr) {
        this.canReady = cr;
    }

    public void setPinReady(final boolean pr) {
        this.pinReady = pr;
    }

    public boolean getCanReady() {
        return this.canReady;
    }

    public boolean getPinReady() {
        return this.pinReady;
    }
}
