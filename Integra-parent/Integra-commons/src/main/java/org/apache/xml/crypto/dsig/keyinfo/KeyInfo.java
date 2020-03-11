/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
/*
 * $Id: KeyInfo.java 1092655 2011-04-15 10:24:18Z coheigea $
 */
package org.apache.xml.crypto.dsig.keyinfo;

import java.util.List;
import org.apache.xml.crypto.MarshalException;
import org.apache.xml.crypto.XMLCryptoContext;
import org.apache.xml.crypto.XMLStructure;

/**
 * A representation of the XML <code>KeyInfo</code> element as defined in
 * the <a href="http://www.w3.org/TR/xmldsig-core/">
 * W3C Recommendation for XML-Signature Syntax and Processing</a>.
 * A <code>KeyInfo</code> contains a list of {@link XMLStructure}s, each of 
 * which contain information that enables the recipient(s) to obtain the key 
 * needed to validate an XML signature. The XML Schema Definition is defined as:
 *
 * <pre>
 * &lt;element name="KeyInfo" type="ds:KeyInfoType"/&gt; 
 * &lt;complexType name="KeyInfoType" mixed="true"&gt;
 *   &lt;choice maxOccurs="unbounded"&gt;     
 *     &lt;element ref="ds:KeyName"/&gt; 
 *     &lt;element ref="ds:KeyValue"/&gt; 
 *     &lt;element ref="ds:RetrievalMethod"/&gt;
 *     &lt;element ref="ds:X509Data"/&gt;
 *     &lt;element ref="ds:PGPData"/&gt;
 *     &lt;element ref="ds:SPKIData"/&gt;
 *     &lt;element ref="ds:MgmtData"/&gt;
 *     &lt;any processContents="lax" namespace="##other"/&gt;
 *     &lt;!-- (1,1) elements from (0,unbounded) namespaces --&gt;
 *   &lt;/choice&gt;
 *   &lt;attribute name="Id" type="ID" use="optional"/&gt; 
 * &lt;/complexType&gt;
 * </pre>
 * 
 * A <code>KeyInfo</code> instance may be created by invoking one of the 
 * {@link KeyInfoFactory#newKeyInfo newKeyInfo} methods of the
 * {@link KeyInfoFactory} class, and passing it a list of one or more 
 * <code>XMLStructure</code>s and an optional id parameter;
 * for example:
 * <pre>
 *   KeyInfoFactory factory = KeyInfoFactory.getInstance("DOM");
 *   KeyInfo keyInfo = factory.newKeyInfo
 *	(Collections.singletonList(factory.newKeyName("Alice"), "keyinfo-1"));
 * </pre>
 *
 * <p><code>KeyInfo</code> objects can also be marshalled to XML by invoking
 * the {@link #marshal marshal} method.
 *
 * @author Sean Mullan
 * @author JSR 105 Expert Group
 * @see KeyInfoFactory#newKeyInfo(List)
 * @see KeyInfoFactory#newKeyInfo(List, String)
 */
public interface KeyInfo extends XMLStructure {

    /**
     * Returns an {@link java.util.Collections#unmodifiableList unmodifiable 
     * list} containing the key information. Each entry of the list is 
     * an {@link XMLStructure}.
     *
     * <p>If there is a public subclass representing the type of 
     * <code>XMLStructure</code>, it is returned as an instance of that
     * class (ex: an <code>X509Data</code> element would be returned as an
     * instance of {@link org.apache.xml.crypto.dsig.keyinfo.X509Data}).
     *
     * @return an unmodifiable list of one or more <code>XMLStructure</code>s 
     *    in this <code>KeyInfo</code>. Never returns <code>null</code> or an
     *    empty list.
     */
    List getContent();

    /**
     * Return the optional Id attribute of this <code>KeyInfo</code>, which
     * may be useful for referencing this <code>KeyInfo</code> from other 
     * XML structures.
     *
     * @return the Id attribute of this <code>KeyInfo</code> (may be 
     *    <code>null</code> if not specified)
     */
    String getId();

    /**
     * Marshals the key info to XML.
     *
     * @param parent a mechanism-specific structure containing the parent node
     *    that the marshalled key info will be appended to
     * @param context the <code>XMLCryptoContext</code> containing additional
     *    context (may be null if not applicable)
     * @throws ClassCastException if the type of <code>parent</code> or
     *    <code>context</code> is not compatible with this key info
     * @throws MarshalException if the key info cannot be marshalled
     * @throws NullPointerException if <code>parent</code> is <code>null</code>
     */
    void marshal(XMLStructure parent, XMLCryptoContext context)
        throws MarshalException;
}