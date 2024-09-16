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
package net.java.xades.security.xml.XAdES;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.tsp.TSPException;
import org.w3c.dom.Document;

import net.java.xades.security.timestamp.TimeStampFactory;

public class IndividualDataObjectsTimeStampImpl implements IndividualDataObjectsTimeStamp {

	private byte[] data;

	public IndividualDataObjectsTimeStampImpl(byte[] data) {
		this.data = data;
	}

	public byte[] generateEncapsulatedTimeStamp(Document parent, String tsaURL)
			throws NoSuchAlgorithmException, IOException, URISyntaxException, TSPException {
		return TimeStampFactory.getTimeStamp(tsaURL, this.data, true);
	}
}
