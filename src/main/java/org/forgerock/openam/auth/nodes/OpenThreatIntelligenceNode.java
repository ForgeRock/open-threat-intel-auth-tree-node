/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 */
/*
 * simon.moffatt@forgerock.com
 *
 * Checks for the presence of the named cookie in the authentication request.  Doesn't check cookie value, only presence
 */

package org.forgerock.openam.auth.nodes;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ResourceBundle;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import org.forgerock.openam.utils.JsonValueBuilder;



@Node.Metadata(outcomeProvider = OpenThreatIntelligenceNode.OutcomeProvider.class,
        configClass = OpenThreatIntelligenceNode.Config.class)
public class OpenThreatIntelligenceNode implements Node {

    private final static String TRUE_OUTCOME_ID = "true";
    private final static String FALSE_OUTCOME_ID = "false";
    private final static String DEBUG_FILE = "OpenThreatIntelligenceNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private static final int MODE_IP_DIRECT = 0;
    private static final int MODE_IP_PROXY = 1;
    private static final int MODE_IP_SHARED_STATE = 2;
    private int modeIP = MODE_IP_DIRECT;
    private String proxyAttribute;
    String currentIP;
    String clientIPAsAString;

    public enum ProxyMode {
        DIRECT,
        PROXY,
        SHARED_STATE
    }

    public interface Config {

        //-- Proxy Mode - DIRECT or PROXY --
        @Attribute(order = 300)
        default ProxyMode proxyMode() { return ProxyMode.DIRECT; }

        //-- Proxy Header --
        @Attribute(order = 310)
        default String proxyAttribute() {
            return "x-forwarded-for";
        }

    }

    private final Config config;



    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public OpenThreatIntelligenceNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }




    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        debug.message("[" + DEBUG_FILE + "]: Started");
        Action.ActionBuilder action;
        JsonValue newState = context.sharedState.copy();
        loadConfig();
        setCurrentIP(context);
        hashIP();

        //Call helper function to see if IP hash is known
        return isIPMalicious(clientIPAsAString);

    }

    private void hashIP() {

        //Create sha256 hash of the IP....
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] clientIPHash = digest.digest(currentIP.getBytes(StandardCharsets.UTF_8));
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < clientIPHash.length; i++) {
            String hex = Integer.toHexString(0xff & clientIPHash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        clientIPAsAString = hexString.toString();

        debug.message("[" + DEBUG_FILE + "]: sha256 hash of client IP created as :" + clientIPAsAString);
    }

    private Action isIPMalicious(String ipHash) {
        String json = "";

        try {

            URL url = new URL("https://api.cymon.io/v2/ioc/search/sha256/" + ipHash);
            debug.message("[" + DEBUG_FILE + "]: Sending request to OTT as " + url);

            //Build HTTP request
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.33 Safari/537.36");
            if (conn.getResponseCode() == 404) {
                debug.message("[" + DEBUG_FILE + "]: response 404 - no breaches found");
                return goTo(false).build();
            }
            if (conn.getResponseCode() != 200) {
                debug.message("[" + DEBUG_FILE + "]: HTTP failed, response code:" + conn.getResponseCode());
                throw new RuntimeException("[" + DEBUG_FILE + "]: HTTP error code : " + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                json = json + output;
            }

            conn.disconnect();

            debug.message("[" + DEBUG_FILE + "]: response from OTT: " + json);

            JsonValue otiResponseObj = JsonValueBuilder.toJsonValue(json);

            debug.message("[" + DEBUG_FILE + "]: response from OTT as JSON: " + otiResponseObj);

            JsonValue total = otiResponseObj.get("total");

            debug.message("[" + DEBUG_FILE + "]: total from OTT: " + total);


            //0 in total attribute means no matches so send to false/Non-Malicious
            if (total.asInteger().equals(0)) {

                debug.message("[" + DEBUG_FILE + "]: IP not from known malicious host");
                return goTo(false).build();

            } else {

                debug.message("[" + DEBUG_FILE + "]: IP from known malicious host");
                return goTo(true).build();
            }



        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return goTo(true).build();
    }



    private Action.ActionBuilder goTo(boolean outcome) {
        return Action.goTo(outcome ? TRUE_OUTCOME_ID : FALSE_OUTCOME_ID);

    }

    private void loadConfig() {
        ProxyMode proxyMode = config.proxyMode();
        debug.message("[" + DEBUG_FILE + "]: GeoLocationNode::process().proxyMode : " + proxyMode);
        switch (proxyMode) {
            case DIRECT:
                debug.message("[" + DEBUG_FILE + "]: modeIP is set to MODE_IP_DIRECT");
                modeIP = MODE_IP_DIRECT;
                break;
            case PROXY:
                debug.message("[" + DEBUG_FILE + "]: modeIP is set to MODE_CHECK");
                modeIP = MODE_IP_PROXY;
                break;
            case SHARED_STATE:
                debug.message("[" + DEBUG_FILE + "]: modeIP is set to MODE_SHARED_STATE");
                modeIP = MODE_IP_SHARED_STATE;
                break;
            default:
                debug.message("[" + DEBUG_FILE + "]: modeIP not specified - default MODE_IP_DIRECT is used");
                modeIP = MODE_IP_DIRECT;
                break;
        }
        proxyAttribute = config.proxyAttribute();
        debug.message("[" + DEBUG_FILE + "]: proxyAttribute : " + proxyAttribute);

    }

    public String parseIP (String ip) {
        if (ip.substring(0,1).equals("[")) {
            return ip.substring(1,ip.length()-1);
        } else {
            return ip;
        }
    }
    private void setCurrentIP(TreeContext context)  {
        try {
            switch (modeIP) {
                case MODE_IP_DIRECT:
                    currentIP = parseIP(context.request.clientIp.toString());
                    if (currentIP.substring(currentIP.length()).equals("]")) currentIP = currentIP.substring(1,currentIP.length()-1);
                    debug.message("[" + DEBUG_FILE + "]: currentIP().IP : " + currentIP);
                    break;
                case MODE_IP_PROXY:
                    if (proxyAttribute.length() > 0) {
                        currentIP = parseIP(context.request.headers.get(proxyAttribute).toString());
                        debug.message("[" + DEBUG_FILE + "]: currentIP().IP : " + currentIP);
                    } else {
                        debug.error("[" + DEBUG_FILE + "]: The header name must be specified if node is configured in proxy mode.");
                    }
                    break;
                case MODE_IP_SHARED_STATE:
                    if (proxyAttribute.length() > 0) {
                        String stringIP;
                        stringIP = parseIP(context.sharedState.get(proxyAttribute).asString());
                        if (stringIP.startsWith("\"")) {
                            stringIP = stringIP.substring(1, stringIP.length());
                        }
                        if (stringIP.endsWith("\"")) {
                            stringIP = stringIP.substring(0, stringIP.length() - 1);
                        }

                        //currentIP = parseIP(context.sharedState.get(proxyAttribute).asString()) + "::" + Instant.now().toString();
                        currentIP = stringIP;
                        debug.message("[" + DEBUG_FILE + "]: SHARED STATE CURRENT IP:" + currentIP);

                        debug.message("[" + DEBUG_FILE + "]: setCurrentIP().IP : " + currentIP);
                    } else {
                        debug.message("[" + DEBUG_FILE + "]: The shared state attribute name must be specified if node is configured in shared state mode.");
                    }
                    break;
            }

        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: The current IP could not be saved.");
        }
    }

    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = OpenThreatIntelligenceNode.class.getName().replace(".", "/");

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(TRUE_OUTCOME_ID, bundle.getString("true")),
                    new Outcome(FALSE_OUTCOME_ID, bundle.getString("false")));
        }
    }
}
