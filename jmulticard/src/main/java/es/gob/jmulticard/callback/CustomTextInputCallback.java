package es.gob.jmulticard.callback;

/*
 * Copyright (c) 1999, 2003, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import javax.security.auth.callback.Callback;

/** <i>Callback</i> de solicitud de texto.
 * &Uacute;til en el caso de Android, que carece de la clase de Java
 * <code>javax.security.auth.callback.TextInputCallback</code>. */
public final class CustomTextInputCallback implements Callback, java.io.Serializable {

    private static final long serialVersionUID = -8064222478852811804L;

    /** Mensaje a mostrar al usuario para solicitarle el texto. Puede ser nulo. */
    private final String prompt;

    /** Texto introducido. */
    private String inputText;

    /** Crea una <i>callback</i> de solicitud de texto.
     * @param p Mensaje a mostrar al usuario para solicitarle el texto. Puede ser nulo. */
    public CustomTextInputCallback(final String p) {
    	this.prompt = p;
    }

    /** Crea una <i>callback</i> de solicitud de texto. */
    public CustomTextInputCallback() {
    	this.prompt = null;
    }

    /** Establece el texto recuperado.
     * @param text Texto recuperado. Puede ser nulo.
     * @see #getText */
    public void setText(final String text) {
        this.inputText = text;
    }

    /** Obtiene el texto recuperado.
     * @return Texto recuperado, puede ser nulo.
     * @see #setText */
    public String getText() {
        return this.inputText;
    }

    /** Obtiene el mensaje a mostrar al usuario para solicitarle el texto.
     * @return Mensaje a mostrar al usuario para solicitarle el texto. Puede ser nulo. */
    public String getPrompt() {
    	return this.prompt;
    }
}