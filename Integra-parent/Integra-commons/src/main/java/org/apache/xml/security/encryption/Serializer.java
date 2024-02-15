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
package org.apache.xml.security.encryption;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.apache.xml.security.c14n.Canonicalizer;

/**
 * Converts <code>String</code>s into <code>Node</code>s and visa versa.
 */
public interface Serializer {
    
    /**
     * Set the Canonicalizer object to use.
     */
    void setCanonicalizer(Canonicalizer canon);
    
    /**
     * Returns a <code>String</code> representation of the specified
     * <code>Element</code>.
     *
     * @param element the <code>Element</code> to serialize.
     * @return the <code>String</code> representation of the serilaized
     *   <code>Element</code>.
     * @throws Exception
     */
    String serialize(Element element) throws Exception;

    /**
     * Returns a <code>String</code> representation of the specified
     * <code>NodeList</code>.
     * 
     * @param content the <code>NodeList</code> to serialize.
     * @return the <code>String</code> representation of the serialized
     *   <code>NodeList</code>.
     * @throws Exception
     */
    String serialize(NodeList content) throws Exception;

    /**
     * Use the Canonicalizer to serialize the node
     * @param node
     * @return the canonicalization of the node
     * @throws Exception
     */ 
    String canonSerialize(Node node) throws Exception;

    /**
     * @param source
     * @param ctx
     * @return the Node resulting from the parse of the source
     * @throws XMLEncryptionException
     */
    Node deserialize(String source, Node ctx) throws XMLEncryptionException;
}