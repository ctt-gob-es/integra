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
package es.gob.afirma.xml.security.transforms.implementations;

import java.io.OutputStream;

import org.w3c.dom.Element;

import es.gob.afirma.xml.security.c14n.CanonicalizationException;
import es.gob.afirma.xml.security.c14n.implementations.Canonicalizer20010315ExclWithComments;
import es.gob.afirma.xml.security.exceptions.XMLSecurityException;
import es.gob.afirma.xml.security.signature.XMLSignatureInput;
import es.gob.afirma.xml.security.transforms.Transform;
import es.gob.afirma.xml.security.transforms.TransformSpi;
import es.gob.afirma.xml.security.transforms.Transforms;
import es.gob.afirma.xml.security.transforms.params.InclusiveNamespaces;
import es.gob.afirma.xml.security.utils.XMLUtils;

/**
 * Implements the <CODE>http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments</CODE>
 * transform.
 *
 * @author Christian Geuer-Pollmann
 */
public class TransformC14NExclusiveWithComments extends TransformSpi {

    /** Field implementedTransformURI */
    public static final String implementedTransformURI =
        Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS;

    /**
     * Method engineGetURI	
     *@inheritDoc 
     *
     */
    protected String engineGetURI() {
        return implementedTransformURI;
    }

    protected XMLSignatureInput enginePerformTransform(
        XMLSignatureInput input, OutputStream os, Transform transformObject
    ) throws CanonicalizationException {
        try {
            String inclusiveNamespaces = null;

            if (transformObject.length(
                InclusiveNamespaces.ExclusiveCanonicalizationNamespace, 
                InclusiveNamespaces._TAG_EC_INCLUSIVENAMESPACES) == 1
            ) {
                Element inclusiveElement =
                    XMLUtils.selectNode(
                        transformObject.getElement().getFirstChild(),
                        InclusiveNamespaces.ExclusiveCanonicalizationNamespace,
                        InclusiveNamespaces._TAG_EC_INCLUSIVENAMESPACES,
                        0
                    );

                inclusiveNamespaces = 
                    new InclusiveNamespaces(
                        inclusiveElement, transformObject.getBaseURI()
                    ).getInclusiveNamespaces();
            }

            Canonicalizer20010315ExclWithComments c14n =
                new Canonicalizer20010315ExclWithComments();        
            if (os != null) {
                c14n.setWriter(os);
            }
            byte[] result = c14n.engineCanonicalize(input, inclusiveNamespaces);
            XMLSignatureInput output = new XMLSignatureInput(result);

            return output;
        } catch (XMLSecurityException ex) {
            throw new CanonicalizationException("empty", ex);
        } 
    }
}
