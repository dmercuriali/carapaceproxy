/*
 Licensed to Diennea S.r.l. under one
 or more contributor license agreements. See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership. Diennea S.r.l. licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.

 */
package nettyhttpproxy.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Raw Socket based Http Client, very useful to reproduce weird behaviours
 */
public final class RawHttpClient implements AutoCloseable {

    private Socket socket;
    private final String host;

    public RawHttpClient(String host, int port) throws IOException {
        socket = new Socket(host, port);
        socket.setSoTimeout(1000);
        this.host = host;
    }

    public OutputStream getOutputStream() throws IOException {
        return socket.getOutputStream();
    }

    public InputStream getInputStream() throws IOException {
        return socket.getInputStream();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    public HttpResponse get(String uri) throws IOException {
        return executeRequest("GET " + uri + " HTTP/1.1\r\nHost:" + host + "\r\nConnection: keep-alive\r\n\r\n");
    }

    public void sendRequest(String request) throws IOException {
        sendRequest(request.getBytes(StandardCharsets.UTF_8));
    }

    public void sendRequest(byte[] request) throws IOException {
        OutputStream oo = socket.getOutputStream();
        oo.write(request);
        oo.flush();
    }

    private static class BufferedStream extends OutputStream {

        final OutputStream wrapped;
        final ByteArrayOutputStream buffer;

        public BufferedStream(OutputStream wrapped) {
            this.wrapped = wrapped;
            this.buffer = new ByteArrayOutputStream();
        }

        @Override
        public void write(int b) throws IOException {
            wrapped.write(b);
            buffer.write(b);
        }

        @Override
        public String toString() {
            try {
                return "BufferedStream{buffer=" + buffer.toString("utf-8") + '}';
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }

    }

    public static final class HttpResponse {

        ByteArrayOutputStream rawResponse = new ByteArrayOutputStream();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        List<String> headerLines = new ArrayList<>();
        String statusLine;
        int expectedContentLength = -1;

        public int getExpectedContentLength() {
            return expectedContentLength;
        }

        public List<String> getHeaderLines() {
            return headerLines;
        }

        public String getStatusLine() {
            return statusLine;
        }

        public byte[] getFull() {
            return rawResponse.toByteArray();
        }

        public byte[] getBody() {
            return body.toByteArray();
        }

        public String getBodyString() throws UnsupportedEncodingException {
            return body.toString("utf-8");
        }

        @Override
        public String toString() {
            try {
                return rawResponse.toString("utf-8");
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        }

    }

    private static HttpResponse consumeHttpResponseInput(final InputStream in) throws IOException {

        HttpResponse result = new HttpResponse();

        BufferedStream firstLine = new BufferedStream(result.rawResponse);
        consumeLFEndedLine(in, firstLine);
        result.statusLine = firstLine.buffer.toString("utf-8");

        // header
        while (true) {
            BufferedStream counter = new BufferedStream(result.rawResponse);
            consumeLFEndedLine(in, counter);
            String line = counter.buffer.toString("utf-8");
            System.out.println("READ HEADER " + line.trim() + " size " + counter.buffer.size());
            if (counter.buffer.size() <= 2) {
                System.out.println("END OF HEADER");
                // end of header
                break;
            } else {

                result.headerLines.add(line);
                if (line.startsWith("Content-Length:")) {
                    result.expectedContentLength = Integer.parseInt(line.substring("Content-Length:".length()).trim());
                    System.out.println("expectedContentLength:" + result.expectedContentLength);
                }
            }
        }
        if (result.expectedContentLength == 0) {
            System.out.println("END OF BODY content-len 0");
            return result;
        }

        // body
        int b = in.read();
        while (b != -1) {
            result.rawResponse.write(b);
            result.body.write(b);

            if (result.expectedContentLength > 0 && result.body.size() == result.expectedContentLength) {
                System.out.println("END OF BODY content-len " + result.expectedContentLength);
                return result;
            }

            b = in.read();
        }
        if (result.expectedContentLength > 0 && result.body.size() < result.expectedContentLength) {
            throw new IOException("Incomplete response, expected Content-Length: " + result.expectedContentLength + ", but read only " + result.body.size());
        }
        System.out.println("END OF BODY");
        return result;
    }

    private static void consumeLFEndedLine(final InputStream in, OutputStream responseReceived) throws IOException {
        int b = in.read();
        while (b != -1) {
            responseReceived.write(b);
            if (b == '\n') {
                break;
            }
            b = in.read();
        }
    }

    public HttpResponse executeRequest(String request) throws IOException {
        sendRequest(request.getBytes(StandardCharsets.UTF_8));
        return consumeHttpResponseInput(socket.getInputStream());
    }

    public HttpResponse readResponse() throws IOException {
        return consumeHttpResponseInput(socket.getInputStream());
    }

}