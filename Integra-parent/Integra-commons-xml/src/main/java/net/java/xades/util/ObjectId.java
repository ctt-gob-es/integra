// Copyright (C) 2012-13 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and
// more details.
// You should have received a copy of the EUPL1.1 license
// along with this program; if not, you may find it at
// https://eupl.eu/1.1/es/

/*
 * This file is part of the jXAdES library. 
 * jXAdES is an open implementation for the Java platform of the XAdES standard for advanced XML digital signature. 
 * This library can be consulted and downloaded from http://universitatjaumei.jira.com/browse/JXADES.
 * 
 */
package net.java.xades.util;

import java.io.IOException;

/**
 *
 * @author miro
 */
public class ObjectId implements Comparable<ObjectId> {

    protected final int[ ] components;
    private final int hashCode;
    private String toString;

    public ObjectId(int[ ] components) {
	if (components == null || components.length <= 0)
	    throw new IllegalArgumentException("Components[] parameter can not be NULL or empty.");

	this.components = components.clone();

	int componentLen = components.length;
	int hc = componentLen;
	for (int i = 0; i < componentLen; i++)
	    hc += components[i] * 37;
	hashCode = hc;
    }

    public ObjectId(String componentsString) throws IOException {
	this(parseObjectIdentifierString(componentsString));
    }

    public boolean equals(Object other) {
	if (this == other)
	    return true;

	if (!(other instanceof ObjectId))
	    return false;

	return compareTo((ObjectId) other) == 0;
    }

    public int compareTo(ObjectId other) {
	int size;
	if (components.length < other.components.length)
	    size = components.length;
	else
	    size = other.components.length;

	int i = 0;
	while (i < size) {
	    int result = components[i] - other.components[i];
	    if (result != 0)
		return result;
	    i++;
	}

	return components.length - other.components.length;
    }

    public int[ ] getComponents() {
	return components.clone();
    }

    public String toString() {
	if (toString == null) {
	    StringBuilder sb = new StringBuilder();
	    for (int i = 0; i < components.length; i++) {
		if (i > 0)
		    sb.append('.');
		sb.append(components[i]);
	    }

	    toString = sb.toString();
	}

	return toString;
    }

    public int hashCode() {
	return hashCode;
    }

    private static int[ ] parseObjectIdentifierString(String objId) throws IOException {
	try {
	    String[ ] strValues = objId.split("\\.");
	    int[ ] intValues = new int[strValues.length];
	    for (int i = 0; i < strValues.length; i++) {
		intValues[i] = Integer.parseInt(strValues[i].trim());
	    }

	    return intValues;
	} catch (Exception ex) {
	    throw new IOException("Invalid ObjectId format: " + objId + " - " + ex.toString());
	}
    }
}
