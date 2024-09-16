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

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * Factory class for interacting with Time Stamp Authority (TSA) services to obtain time stamps.
 */
public class TimeStampFactory {

    /**
     * Creates a time stamp request, sends it to a TSA server, and processes the response.
     *
     * @param tsaUri The URI of the TSA server.
     * @param data The data to be time-stamped.
     * @param calculateDigest If true, a digest of the data will be calculated before the request.
     * @return The TSA response containing the time stamp token.
     * @throws NoSuchAlgorithmException If the specified algorithm is not available.
     * @throws IOException If an I/O error occurs during communication with the TSA server.
     * @throws TSPException If there is an error processing the TSA response.
     */
    public static TimeStampResponse getTimeStampResponse(URI tsaUri, byte[] data, boolean calculateDigest)
            throws NoSuchAlgorithmException, IOException, TSPException {
        
        byte[] digest = data;

        if (calculateDigest) {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            digest = messageDigest.digest(data);
        }

        // Create the time stamp request using Bouncy Castle
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(false); // Request certificate in the response
        TimeStampRequest request = tsqGenerator.generate(
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), // OID for SHA-256
                digest, BigInteger.valueOf(new Date().getTime()));

        // Send the TSA request over HTTP
        byte[] requestBytes = request.getEncoded();
        byte[] responseBytes = sendTSARequest(tsaUri.toString(), requestBytes);

        // Process the TSA response using Bouncy Castle
        return new TimeStampResponse(responseBytes);
    }

    /**
     * Sends a time stamp request to a TSA server and returns the response.
     *
     * @param tsaUrl The URL of the TSA server.
     * @param requestBytes The request data in binary format.
     * @return The TSA response in binary format.
     * @throws IOException If an I/O error occurs during communication with the TSA server.
     */
    private static byte[] sendTSARequest(String tsaUrl, byte[] requestBytes) throws IOException {
        URL url = new URL(tsaUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/timestamp-query");
        con.setRequestProperty("Content-Length", String.valueOf(requestBytes.length));

        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.write(requestBytes);
        }

        if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Error in TSA connection: " + con.getResponseCode() + " " + con.getResponseMessage());
        }

        try (ByteArrayInputStream bis = new ByteArrayInputStream(con.getInputStream().readAllBytes())) {
            return bis.readAllBytes(); // Read the response in binary format
        }
    }

    /**
     * Obtains a time stamp for the given data from the specified TSA server.
     *
     * @param tsaURL The URL of the TSA server.
     * @param data The data to be time-stamped.
     * @param calculateDigest If true, a digest of the data will be calculated before the request.
     * @return The time stamp in binary format.
     * @throws NoSuchAlgorithmException If the specified algorithm is not available.
     * @throws IOException If an I/O error occurs during communication with the TSA server.
     * @throws TSPException If there is an error processing the TSA response.
     * @throws URISyntaxException If the TSA URL is invalid.
     */
    public static byte[] getTimeStamp(String tsaURL, byte[] data, boolean calculateDigest)
            throws NoSuchAlgorithmException, IOException, TSPException, URISyntaxException {

        URI tsaUri = new URI(tsaURL);
        TimeStampResponse response = getTimeStampResponse(tsaUri, data, calculateDigest);

        return response.getTimeStampToken().getEncoded();
    }
}
