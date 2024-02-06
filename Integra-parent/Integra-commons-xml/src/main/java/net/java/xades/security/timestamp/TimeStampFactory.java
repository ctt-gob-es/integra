// Copyright (C) 2017 MINHAP, Gobierno de España
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

package net.java.xades.security.timestamp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import sun.security.timestamp.HttpTimestamper;
import sun.security.timestamp.TSRequest;
import sun.security.timestamp.TSResponse;

public class TimeStampFactory {

    public static TSResponse getTimeStampResponse(URI strUri, byte[ ] data, boolean calculateDigest) throws NoSuchAlgorithmException, IOException, SignatureException {
	HttpTimestamper httpTimestamper = new HttpTimestamper(strUri);

	byte[ ] digest = data;

	if (calculateDigest) {
	    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
	    digest = messageDigest.digest(data);
	}

	TSRequest request = new TSRequest(null, digest, MessageDigest.getInstance("SHA-1"));
	request.requestCertificate(false);

	TSResponse response = httpTimestamper.generateTimestamp(request);

	return response;
    }

    public static byte[ ] getTimeStamp(String tsaURL, byte[ ] data, boolean calculateDigest) throws NoSuchAlgorithmException, IOException, SignatureException, URISyntaxException {
	TSResponse response = getTimeStampResponse(new URI(tsaURL), data, calculateDigest);

	return response.getEncodedToken();
    }
}
