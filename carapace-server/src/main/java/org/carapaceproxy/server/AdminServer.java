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
package org.carapaceproxy.server;

import io.prometheus.client.exporter.MetricsServlet;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.EnumSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.DispatcherType;
import org.apache.commons.configuration.ConfigurationException;
import org.carapaceproxy.api.ApplicationConfig;
import org.carapaceproxy.api.AuthAPIRequestsFilter;
import org.carapaceproxy.api.ForceHeadersAPIRequestsFilter;
import org.carapaceproxy.configstore.ConfigurationStore;
import org.carapaceproxy.server.config.ConfigurationNotValidException;
import org.carapaceproxy.user.UserRealm;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;
import org.glassfish.jersey.servlet.ServletContainer;
import static org.glassfish.jersey.servlet.ServletProperties.JAXRS_APPLICATION_CLASS;

/**
 *
 * @author dennis.mercuriali
 */
public class AdminServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(AdminServer.class.getName());

    private final File basePath;
    private boolean started = false;

    private Server server;
    private String accessLogPath = "admin.access.log";
    private String accessLogTimezone = "GMT";
    private int accessLogRetentionDays = 90;
    private boolean serverEnabled;
    private int httpPort = -1;
    private String host = "localhost";
    private int httpsPort = -1;
    private String certFile;
    private String certFilePwd;
    private String metricsUrl;

    public AdminServer(File basePath) throws NumberFormatException, ConfigurationNotValidException {
        this.basePath = basePath;
    }

    public void applyConfiguration(ConfigurationStore properties) throws NumberFormatException, ConfigurationNotValidException {
        if (started) {
            throw new IllegalStateException("server already started");
        }

        serverEnabled = Boolean.parseBoolean(properties.getProperty("http.admin.enabled", "false"));
        httpPort = Integer.parseInt(properties.getProperty("http.admin.port", httpPort + ""));
        host = properties.getProperty("http.admin.host", host);
        httpsPort = Integer.parseInt(properties.getProperty("https.admin.port", httpsPort + ""));
        certFile = properties.getProperty("https.admin.sslcertfile", certFile);
        certFilePwd = properties.getProperty("https.admin.sslcertfilepassword", certFilePwd);

        accessLogPath = properties.getProperty("admin.accesslog.path", accessLogPath);
        accessLogTimezone = properties.getProperty("admin.accesslog.format.timezone", accessLogTimezone);
        accessLogRetentionDays = Integer.parseInt(properties.getProperty("admin.accesslog.retention.days", accessLogRetentionDays + ""));

        LOG.info("http.admin.enabled=" + serverEnabled);
        LOG.info("http.admin.port=" + httpPort);
        LOG.info("http.admin.host=" + host);
        LOG.info("https.admin.port=" + httpsPort);
        LOG.info("https.admin.sslcertfile=" + certFile);
    }

    public void start(HttpProxyServer proxyServer) throws Exception {
        if (!serverEnabled) {
            return;
        }

        if (httpPort < 0 && httpsPort < 0) {
            throw new RuntimeException("To enable admin interface at least one between http and https port must be set");
        }
        
        started = true;

        enableDefaultMetrics();

        server = new Server();

        ServerConnector httpConnector = null;
        if (httpPort >= 0) {
            LOG.info("Starting Admin UI over HTTP");

            httpConnector = new ServerConnector(server);
            httpConnector.setPort(httpPort);
            httpConnector.setHost(host);

            server.addConnector(httpConnector);
        }

        ServerConnector httpsConnector = null;
        if (httpsPort >= 0) {
            LOG.info("Starting Admin UI over HTTPS");

            File sslCertFile = certFile.startsWith("/") 
                ? new File(certFile) 
                : new File(basePath, certFile);
            sslCertFile = sslCertFile.getAbsoluteFile();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream in = new FileInputStream(sslCertFile)) {
                ks.load(in, certFilePwd.trim().toCharArray());
            }

            SslContextFactory sslContextFactory = new SslContextFactory();
            sslContextFactory.setKeyStore(ks);
            sslContextFactory.setKeyStorePassword(certFilePwd);
            sslContextFactory.setKeyManagerPassword(certFilePwd);

            HttpConfiguration https = new HttpConfiguration();
            https.setSecurePort(httpsPort);
            https.addCustomizer(new SecureRequestCustomizer());

            httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"),
                new HttpConnectionFactory(https));
            httpsConnector.setPort(httpsPort);
            httpsConnector.setHost(host);

            server.addConnector(httpsConnector);
        }

        ContextHandlerCollection contexts = new ContextHandlerCollection();
        server.setHandler(contexts);

        File webUi = new File(basePath, "web/ui");
        if (webUi.isDirectory()) {
            WebAppContext webApp = new WebAppContext(webUi.getAbsolutePath(), "/ui");
            contexts.addHandler(webApp);
        } else {
            LOG.severe("Cannot find " + webUi.getAbsolutePath() + " directory. Web UI will not be deployed");
        }

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.GZIP);
        context.setContextPath("/");
        context.addFilter(AuthAPIRequestsFilter.class, "/api/*", EnumSet.of(DispatcherType.REQUEST));
        context.addFilter(ForceHeadersAPIRequestsFilter.class, "/api/*", EnumSet.of(DispatcherType.REQUEST));
        ServletHolder jerseyServlet = new ServletHolder(new ServletContainer());
        jerseyServlet.setInitOrder(0);
        jerseyServlet.setInitParameter(JAXRS_APPLICATION_CLASS, ApplicationConfig.class.getCanonicalName());
        context.addServlet(jerseyServlet, "/api/*");
        context.addServlet(new ServletHolder(new MetricsServlet()), "/metrics");
        context.setAttribute("adminserver", this);
        context.setAttribute("server", proxyServer);

        NCSARequestLog requestLog = new NCSARequestLog();
        requestLog.setFilename(accessLogPath);
        requestLog.setFilenameDateFormat("yyyy-MM-dd");
        requestLog.setRetainDays(accessLogRetentionDays);
        requestLog.setAppend(true);
        requestLog.setExtended(true);
        requestLog.setLogCookies(false);
        requestLog.setLogTimeZone(accessLogTimezone);
        RequestLogHandler requestLogHandler = new RequestLogHandler();
        requestLogHandler.setRequestLog(requestLog);
        requestLogHandler.setHandler(context);

        contexts.addHandler(requestLogHandler);

        server.start();

        LOG.info("Admin UI started");

        if (httpPort == 0 && httpConnector != null) {
            httpPort = httpConnector.getLocalPort();
        }
        if (httpsPort == 0 && httpsConnector != null) {
            httpsPort = httpsConnector.getLocalPort();
        }

        if (httpPort > 0) {
            LOG.info("Base HTTP Admin UI url: http://" + host + ":" + httpPort + "/ui");
            LOG.info("Base HTTP Admin API url: http://" + host + ":" + httpPort + "/api");
        }
        if (httpsPort > 0) {
            LOG.info("Base HTTPS Admin UI url: https://" + host + ":" + httpsPort + "/ui");
            LOG.info("Base HTTPS Admin API url: https://" + host + ":" + httpsPort + "/api");
        }

        if (httpPort > 0) {
            metricsUrl = "http://" + host + ":" + httpPort + "/metrics";
        } else {
            metricsUrl = "https://" + host + ":" + httpsPort + "/metrics";
        }
        LOG.info("Prometheus Metrics url: " + metricsUrl);

    }

    private void enableDefaultMetrics() throws ConfigurationException {
        try {
            io.prometheus.client.hotspot.DefaultExports.initialize();
        } catch (IllegalArgumentException exc) {
            //default metrics already initialized...ok
        }
    }

    @Override
    public void close() {
        if (server != null) {
            try {
                server.stop();
            } catch (Exception err) {
                LOG.log(Level.SEVERE, "Error while stopping admin server", err);
            } finally {
                server = null;
            }
        }
    }

    public int getAdminServerHttpPort() {
        return httpPort;
    }

    public String getAdminServerHost() {
        return host;
    }

    public int getAdminServerHttpsPort() {
        return httpsPort;
    }

    public String getMetricsUrl() {
        return metricsUrl;
    }
    
}
