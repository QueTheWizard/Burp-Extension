package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.*;
import java.net.URL;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;

public class BurpExtender implements IBurpExtender, ITab, IScannerCheck {

    Boolean isDebugging = false;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter mStdOut;
    private PrintWriter mStdErr;

//    private static final byte[] INJ_TEST = "\"||calc||".getBytes();
//    private static final byte[] INJ_ERROR = "\"||calc||".getBytes();

    // GUI
    private JTabbedPane topTabs;
    TextArea parametersTextArea = new TextArea();
    TextArea payloadsTextArea = new TextArea();

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.helpers = callbacks.getHelpers();

        this.mStdOut = new PrintWriter(callbacks.getStdout(), true);
        this.mStdErr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName("Secrets Sniffer");

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        // GUI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // Declare and initialize all tabs
                topTabs = new JTabbedPane();
                JPanel keyHacksPanel = new JPanel();
                keyHacksPanel.setLayout(new BoxLayout (keyHacksPanel, BoxLayout.Y_AXIS));
//                topTabs.addTab("KeyHacks", keyHacksPanel);
                JPanel checkListPanel = new JPanel();
                checkListPanel.setLayout(new BoxLayout (checkListPanel, BoxLayout.Y_AXIS));
                topTabs.addTab("Check List", checkListPanel);
                burp.about.initializeFunction(topTabs);

                // KeyHacks Tab
                JPanel apiKeysPanel = new JPanel();
                apiKeysPanel.setLayout(new BoxLayout (apiKeysPanel, BoxLayout.X_AXIS));
                apiKeysPanel.add(new JLabel("Google Maps API Key:  "));
                JTextField apiKeyTextField = new JTextField("API Key Here");
                apiKeyTextField.setPreferredSize(new Dimension(200,30));
                apiKeyTextField.setMaximumSize(apiKeyTextField.getPreferredSize());
                apiKeysPanel.add(apiKeyTextField);
                apiKeysPanel.add(new JLabel("  "));
                JButton apiKeyCheckButton = new JButton("GO");
                apiKeysPanel.add(apiKeyCheckButton);
                keyHacksPanel.add(apiKeysPanel);
                apiKeyCheckButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
//                        GET Request to check the API key
//                        https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY_HERE
                    }
                });
                // Clear panel and button KeyHacks tab
//                JPanel clearPanel = new JPanel();
//                clearPanel.setLayout(new BoxLayout (clearPanel, BoxLayout.X_AXIS));
//                JButton clearButtonForKeyHacks = new JButton("Clear");
//                clearPanel.add(clearButtonForKeyHacks);
//                keyHacksPanel.add(clearPanel);
//                clearButtonForKeyHacks.addActionListener(new ActionListener() {
//                    @Override
//                    public void actionPerformed(ActionEvent ae) {
//                        apiKeyTextField.setText(null);
//                    }
//                });

                // Test - JPanel from other class file
                JComponent checkListPanel1 = new CheckListPanel();
                checkListPanel.add(checkListPanel1);

                // customize our UI components
                // callbacks.customizeUiComponent(topTabs); // disabled to be able to drag and drop columns
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "BugSec";
    }

    @Override
    public Component getUiComponent() {
        return topTabs;
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    //
    // implement IScannerCheck
    //
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
//        String parametersFromTextAreaActive[] = parametersTextArea.getText().split("\\n");
//        for (int i = 0; i < parametersFromTextAreaActive.length; i = i + 1) {
//            if (this.helpers.analyzeRequest(baseRequestResponse).getMethod().equals("GET")) {
//                List responseArray = this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders();
//                Iterator headerItr = responseArray.iterator();
//                while (headerItr.hasNext()) {
//                    String header = headerItr.next().toString();
//                    if (header.contains("Content-Type:")) {
//                        if ((header.contains("json")) || (header.contains("javascript"))) {
//                            List parameters = this.helpers.analyzeRequest(baseRequestResponse).getParameters();
//                            Iterator parameterItr = parameters.iterator();
//                            while (parameterItr.hasNext()) {
//                                IParameter parameter = (IParameter) parameterItr.next();
//                                if (parameter.getName().contains(parametersFromTextAreaActive[i])) {
//                                    List issues = new ArrayList(1);
//                                    issues.add(new CustomScanIssue(baseRequestResponse
//                                            .getHttpService(), this.helpers
//                                            .analyzeRequest(baseRequestResponse)
//                                            .getUrl(), new IHttpRequestResponse[0], "Potential RFD Issue Detected", "A parameter named " + parametersFromTextAreaActive[i] + " is detected, this is a potential reflected file download issue, please check this url manually " + this.helpers
//                                            .analyzeRequest(baseRequestResponse)
//                                            .getUrl()
//                                            + "<br><br><b>Issue Definition</b><br><br>"
//                                            + "\"Reflected File Download(RFD) is a web attack vector that enables attackers to gain"
//                                            + " complete control over a victim ’s machine."
//                                            + "In an RFD attack, the user follows a malicious link to a trusted domain resulting in a file download from that domain."
//                                            + "computer.\""
//                                            + "<br><I>Oren Hafif</I>"
//                                            + "<br><br><b>Notes</b><br><br>"
//                                            + "\"In the absence of a filename attribute returned within a Content-Disposition "
//                                            + "response header, browsers are forced to determine the name of a downloaded file "
//                                            + "based on the URL (from the address bar). An attacker can tamper with the \"Path\" "
//                                            + "portion of the URL (between the domain name and the question mark sign \"?\") to "
//                                            + "set malicious extensions for downloads.\""
//                                            + "<br><I>Oren Hafif</I>"
//                                            + "<br><br>Sample URL: <br>https://example.com/api;/setup.bat;/setup.bat<br>"
//                                            + "<br>Sample HTML code using download attribute:<br>&#x3c;&#x61;&#x20;&#x64;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x68;&#x72;&#x65;&#x66;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x63;&#x6f;&#x6d;&#x2f;&#x61;&#x3b;&#x2f;&#x73;&#x65;&#x74;&#x75;&#x70;&#x2e;&#x62;&#x61;&#x74;&#x3b;&#x22;&#x3e;&#x44;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x43;&#x6c;&#x69;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x61;&#x3e;<br>"
//                                            + "<br>Some useful urls to try from https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                            + "https://www.example-site.pt/api/search.bat?term=f00bar&callback=calc<br>"
//                                            + "https://www.example-site.pt/api/search;setup.bat?term=f00bar&callback=calc<br>"
//                                            + "https://www.example-site.pt/api/search/setup.bat?term=f00bar&callback=calc<br>"
//                                            + "https://www.example-site.pt/api/search;/setup.bat?term=f00bar&callback=calc<br>"
//                                            + "https://www.example-site.pt/api/search;/setup.bat;?term=f00bar&callback=calc<br>"
//                                            + "<br><b>References</b><br><br>"
//                                            + "https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf<br>"
//                                            + "https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                            + "<br><br><b>Development Contact Information</b><br><br>"
//                                            + "onur.karasalihoglu@enforsec.com (@onurkarasalih) <br><br>"
//                                            + "Special thanks to Oren Hafif (@orenhafif) for the discovery of this vulnerability and support for this plugin", "Medium"));
//
//                                    return issues;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }

        // Google API match
        String response = helpers.bytesToString(baseRequestResponse.getResponse());
        Pattern googleApiPattern = Pattern.compile("AIzaSy[0-9A-Za-z-_]{33}");
        Matcher googleApiMatcher = googleApiPattern.matcher(response);

        // Google API key matcher
        if (googleApiMatcher.find()) {
            ArrayList<String> matchList = new ArrayList<>();
            while (googleApiMatcher.find()) {
                for (int i = 0; i <= googleApiMatcher.groupCount(); i++) {
                    matchList.add(googleApiMatcher.group(i));
                }
            }
            Object[] newMatchList = matchList.toArray();
            String firstMatchToStr = (String) newMatchList[0];
            final byte[] GREP_STRING = firstMatchToStr.getBytes();
            Set<String> set = new HashSet<>(matchList);
            matchList.clear();
            matchList.addAll(set);
            String setMatchListString = String.join("<br>", set);
            List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                    "Google API Key Detected",
                    "Google API key/s found: <br>" + setMatchListString
                            + "<br><br> KeyHacks URL (only for the first key) - https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=" + helpers.bytesToString(GREP_STRING),
                    "Low", "Certain"));
            return issues;
        }

        // AWS Access Key ID match
        Pattern awsPattern = Pattern.compile("AKIA[0-9A-Z]{16}");
        Matcher awsMatcher = awsPattern.matcher(response);

        if (awsMatcher.find()) {
            ArrayList<String> matchList = new ArrayList<>();
            while (awsMatcher.find()) {
                for (int i = 0; i <= awsMatcher.groupCount(); i++) {
                    matchList.add(awsMatcher.group(i));
                }
            }
            Object[] newMatchList = matchList.toArray();
            String firstMatchToStr = (String) newMatchList[0];
            final byte[] GREP_STRING = firstMatchToStr.getBytes();
            Set<String> set = new HashSet<>(matchList);
            matchList.clear();
            matchList.addAll(set);
            String setMatchListString = String.join("<br>", set);
            List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                    "AWS Access Key Detected",
                    "AWS access key/s found: <br>" + setMatchListString
                            + "<br><br> Test with awscli: <br> AWS_ACCESS_KEY_ID=xxxx AWS_SECRET_ACCESS_KEY=yyyy aws sts get-caller-identity" + helpers.bytesToString(GREP_STRING),
                    "High", "Certain"));
            return issues;
        }

        // Slack API key matcher
        Pattern slackPattern = Pattern.compile("(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})");
        Matcher slackMatcher = slackPattern.matcher(response);

        if (slackMatcher.find()) {
            ArrayList<String> matchList = new ArrayList<>();
            while (slackMatcher.find()) {
                for (int i = 0; i <= slackMatcher.groupCount(); i++) {
                    matchList.add(slackMatcher.group(i));
                }
            }
            Object[] newMatchList = matchList.toArray();
            String firstMatchToStr = (String) newMatchList[0];
            final byte[] GREP_STRING = firstMatchToStr.getBytes();
            Set<String> set = new HashSet<>(matchList);
            matchList.clear();
            matchList.addAll(set);
            String setMatchListString = String.join("<br>", set);
            List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                    "Slack API Key Detected",
                    "Slack api key/s found: <br>" + setMatchListString
                            + "<br><br> Test with curl: curl -sX POST \"https://slack.com/api/auth.test?token=xoxp-TOKEN_HERE&pretty=1\"" + helpers.bytesToString(GREP_STRING),
                    "Low", "Certain"));
            return issues;
        }

        // SendGrid Matcher
        Pattern sendGridPattern = Pattern.compile("SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}");
        Matcher sendGridMatcher = sendGridPattern.matcher(response);

        if (sendGridMatcher.find()) {
            ArrayList<String> matchList = new ArrayList<>();
            while (sendGridMatcher.find()) {
                for (int i = 0; i <= sendGridMatcher.groupCount(); i++) {
                    matchList.add(sendGridMatcher.group(i));
                }
            }
            Object[] newMatchList = matchList.toArray();
            String firstMatchToStr = (String) newMatchList[0];
            final byte[] GREP_STRING = firstMatchToStr.getBytes();
            Set<String> set = new HashSet<>(matchList);
            matchList.clear();
            matchList.addAll(set);
            String setMatchListString = String.join("<br>", set);
            List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                    "SendGrid API Key Detected",
                    "SendGrid api key/s found: <br>" + setMatchListString,
                    "High", "Firm"));
            return issues;
        }

        // Private key Matcher
        Pattern privateKeyPattern = Pattern.compile("(-----(\\bBEGIN\\b|\\bEND\\b) ((\\bRSA PRIVATE KEY\\b)|(\\bCERTIFICATE\\b)|(\\bPGP PRIVATE KEY BLOCK\\b)|(\\bOPENSSH PRIVATE KEY\\b))-----)");
        Matcher privateKeyMatcher = privateKeyPattern.matcher(response);

        if (privateKeyMatcher.find()) {
            ArrayList<String> matchList = new ArrayList<>();
            while (privateKeyMatcher.find()) {
                for (int i = 0; i <= privateKeyMatcher.groupCount(); i++) {
                    matchList.add(privateKeyMatcher.group(i));
                }
            }
            Object[] newMatchList = matchList.toArray();
            String firstMatchToStr = (String) newMatchList[0];
            final byte[] GREP_STRING = firstMatchToStr.getBytes();
            Set<String> set = new HashSet<>(matchList);
            matchList.clear();
            matchList.addAll(set);
            String setMatchListString = String.join("<br>", set);
            List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                    "Cryptographic Private Key Detected",
                    "RSA/PGP/OPENSSH private key/s found: <br>" + setMatchListString,
                    "Medium", "Firm"));
            return issues;
        }
        return null;

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
//        String parametersFromTextAreaActive[] = parametersTextArea.getText().split("\\n");
//        String payloadsFromTextAreaActive[] = payloadsTextArea.getText().split("\\n");
//        if (this.helpers.analyzeRequest(baseRequestResponse).getMethod().equals("GET")) {
//            List responseArray = this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders();
//            Iterator headerItr = responseArray.iterator();
//            while (headerItr.hasNext()) {
//                String header = headerItr.next().toString();
//                if (header.contains("Content-Type:")) {
//                    if ((header.contains("json")) || (header.contains("javascript"))) {
//                        for (String payloadsFromTextAreaActive1 : payloadsFromTextAreaActive) {
//                            // Checking parameter
//                            byte[] checkRequest1 = insertionPoint.buildRequest(helpers.stringToBytes(payloadsFromTextAreaActive1));
//                            IHttpRequestResponse checkRequestResponse1 = this.callbacks.makeHttpRequest(baseRequestResponse
//                                    .getHttpService(), checkRequest1);
//                            List matches1 = getMatches(checkRequestResponse1.getResponse(), helpers.stringToBytes(payloadsFromTextAreaActive1));
//                            if (matches1.size() > 0) {
//                                // Payload reflected in current parameter, if reflected won't continue..
//                                List requestHighlights = new ArrayList(1);
//                                requestHighlights.add(insertionPoint.getPayloadOffsets(helpers.stringToBytes(payloadsFromTextAreaActive1)));
//                                List issues = new ArrayList(1);
//                                issues.add(new CustomScanIssue(baseRequestResponse
//                                        .getHttpService(), this.helpers
//                                        .analyzeRequest(baseRequestResponse)
//                                        .getUrl(), new IHttpRequestResponse[]{this.callbacks
//                                        .applyMarkers(checkRequestResponse1, requestHighlights, matches1)}, "Reflected File Download", "Submitting "+ this.helpers.bytesToString(helpers.stringToBytes(payloadsFromTextAreaActive1)) +" returned the string:" + this.helpers.bytesToString(helpers.stringToBytes(payloadsFromTextAreaActive1)) + "<br><br>"
//                                        + "<b>Issue Definition</b><br><br>"
//                                        + "\"Reflected File Download(RFD) is a web attack vector that enables attackers to gain"
//                                        + " complete control over a victim ’s machine."
//                                        + "In an RFD attack, the user follows a malicious link to a trusted domain resulting in a file download from that domain."
//                                        + "computer.\""
//                                        + "<br><I>Oren Hafif</I>"
//                                        + "<br><br><b>Notes</b><br><br>"
//                                        + "\"In the absence of a filename attribute returned within a Content-Disposition "
//                                        + "response header, browsers are forced to determine the name of a downloaded file "
//                                        + "based on the URL (from the address bar). An attacker can tamper with the \"Path\" "
//                                        + "portion of the URL (between the domain name and the question mark sign \"?\") to "
//                                        + "set malicious extensions for downloads.\""
//                                        + "<br><I>Oren Hafif</I>"
//                                        + "<br><br>Sample URL: <br>https://example.com/api;/setup.bat;/setup.bat<br>"
//                                        + "<br>Sample HTML code using download attribute:<br>&#x3c;&#x61;&#x20;&#x64;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x68;&#x72;&#x65;&#x66;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x63;&#x6f;&#x6d;&#x2f;&#x61;&#x3b;&#x2f;&#x73;&#x65;&#x74;&#x75;&#x70;&#x2e;&#x62;&#x61;&#x74;&#x3b;&#x22;&#x3e;&#x44;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x43;&#x6c;&#x69;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x61;&#x3e;<br>"
//                                        + "<br>Some useful urls to try from https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                        + "https://www.example-site.pt/api/search.bat?term=f00bar&callback=calc<br>"
//                                        + "https://www.example-site.pt/api/search;setup.bat?term=f00bar&callback=calc<br>"
//                                        + "https://www.example-site.pt/api/search/setup.bat?term=f00bar&callback=calc<br>"
//                                        + "https://www.example-site.pt/api/search;/setup.bat?term=f00bar&callback=calc<br>"
//                                        + "https://www.example-site.pt/api/search;/setup.bat;?term=f00bar&callback=calc<br>"
//                                        + "<br> <b>References</b><br><br>"
//                                        + "https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf<br>"
//                                        + "https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                        + "<br><br><b>Development Contact Information</b><br><br>"
//                                        + "onur.karasalihoglu@enforsec.com (@onurkarasalih) <br><br>"
//                                        + "Special thanks to Oren Hafif (@orenhafif) for the discovery of this vulnerability and support for this plugin", "High"));
//                                return issues;
//                            }
//                            for (int i = 0; i < parametersFromTextAreaActive.length; i = i + 1) {
//                                if (isDebugging) {
//                                    mStdOut.println("Checking for parameter " + parametersFromTextAreaActive[i]);
//                                }
//                                byte[] checkRequest = insertionPoint.buildRequest(helpers.stringToBytes(payloadsFromTextAreaActive1));
//                                IHttpRequestResponse checkRequestResponse = this.callbacks.makeHttpRequest(baseRequestResponse
//                                        .getHttpService(), checkRequest);
//                                List parameters = this.helpers.analyzeRequest(baseRequestResponse).getParameters();
//                                Boolean isMatched = false;
//                                for (int z = 0; z < parameters.size(); z++) {
//                                    if (isDebugging) {
//                                        mStdOut.println("Parameter in HTTP request " + ((IParameter) parameters.get(z)).getName());
//                                    }
//                                    if (((IParameter) parameters.get(z)).getName().equals(parametersFromTextAreaActive[i])) {
//                                        // Parameter provided from burp matched in HTTP request
//                                        if (isDebugging) {
//                                            mStdOut.println("matched! " + parametersFromTextAreaActive[i]);
//                                        }
//                                        isMatched = true;
//                                        List matches = getMatches(checkRequestResponse.getResponse(), helpers.stringToBytes(payloadsFromTextAreaActive1));
//                                        if (matches.size() > 0) {
//                                            // Payload matched
//                                            List requestHighlights = new ArrayList(1);
//                                            requestHighlights.add(insertionPoint.getPayloadOffsets(helpers.stringToBytes(payloadsFromTextAreaActive1)));
//                                            List issues = new ArrayList(1);
//                                            issues.add(new CustomScanIssue(baseRequestResponse
//                                                    .getHttpService(), this.helpers
//                                                    .analyzeRequest(baseRequestResponse)
//                                                    .getUrl(), new IHttpRequestResponse[]{this.callbacks
//                                                    .applyMarkers(checkRequestResponse, requestHighlights, matches)}, "Reflected File Download", "Submitting \"||calc|| returned the string:" + this.helpers.bytesToString(helpers.stringToBytes(payloadsFromTextAreaActive1)) + " for " + parametersFromTextAreaActive[i] + " parameter<br><br>"
//                                                    + "<b>Issue Definition</b><br><br>"
//                                                    + "\"Reflected File Download(RFD) is a web attack vector that enables attackers to gain"
//                                                    + " complete control over a victim ’s machine."
//                                                    + "In an RFD attack, the user follows a malicious link to a trusted domain resulting in a file download from that domain."
//                                                    + "computer.\""
//                                                    + "<br><I>Oren Hafif</I>"
//                                                    + "<br><br><b>Notes</b><br><br>"
//                                                    + "\"In the absence of a filename attribute returned within a Content-Disposition "
//                                                    + "response header, browsers are forced to determine the name of a downloaded file "
//                                                    + "based on the URL (from the address bar). An attacker can tamper with the \"Path\" "
//                                                    + "portion of the URL (between the domain name and the question mark sign \"?\") to "
//                                                    + "set malicious extensions for downloads.\""
//                                                    + "<br><I>Oren Hafif</I>"
//                                                    + "<br><br>Sample URL: <br>https://example.com/api;/setup.bat;/setup.bat<br>"
//                                                    + "<br>Sample HTML code using download attribute:<br>&#x3c;&#x61;&#x20;&#x64;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x68;&#x72;&#x65;&#x66;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x63;&#x6f;&#x6d;&#x2f;&#x61;&#x3b;&#x2f;&#x73;&#x65;&#x74;&#x75;&#x70;&#x2e;&#x62;&#x61;&#x74;&#x3b;&#x22;&#x3e;&#x44;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x43;&#x6c;&#x69;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x61;&#x3e;<br>"
//                                                    + "<br>Some useful urls to try from https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                                    + "https://www.example-site.pt/api/search.bat?term=f00bar&callback=calc<br>"
//                                                    + "https://www.example-site.pt/api/search;setup.bat?term=f00bar&callback=calc<br>"
//                                                    + "https://www.example-site.pt/api/search/setup.bat?term=f00bar&callback=calc<br>"
//                                                    + "https://www.example-site.pt/api/search;/setup.bat?term=f00bar&callback=calc<br>"
//                                                    + "https://www.example-site.pt/api/search;/setup.bat;?term=f00bar&callback=calc<br>"
//                                                    + "<br> <b>References</b><br><br>"
//                                                    + "https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf<br>"
//                                                    + "https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                                    + "<br><br><b>Development Contact Information</b><br><br>"
//                                                    + "onur.karasalihoglu@enforsec.com (@onurkarasalih) <br><br>"
//                                                    + "Special thanks to Oren Hafif (@orenhafif) for the discovery of this vulnerability and support for this plugin", "High"));
//                                            return issues;
//                                        }
//                                    }
//                                }
//                                if (!isMatched) {
//                                    // Parameter from plugin GUI cannot be found in HTTP Request
//                                    if (isDebugging) {
//                                        mStdOut.println("Parameter didn't macthed, adding " + parametersFromTextAreaActive[i]);
//                                    }
//                                    // Adding parameter
//                                    IParameter parameter = this.helpers.buildParameter(parametersFromTextAreaActive[i], this.helpers.bytesToString(helpers.stringToBytes(payloadsFromTextAreaActive1)), (byte) 0);
//                                    byte[] newRequest = baseRequestResponse.getRequest();
//                                    newRequest = this.helpers.addParameter(newRequest, parameter);
//                                    // Parameter added to request
//                                    // Making HTTP request
//                                    IHttpRequestResponse checkRequestResponseAdd = this.callbacks.makeHttpRequest(baseRequestResponse
//                                            .getHttpService(), newRequest);
//                                    // Get matches
//                                    List matches = getMatches(checkRequestResponseAdd.getResponse(), helpers.stringToBytes(payloadsFromTextAreaActive1));
//                                    if (matches.size() > 0) {
//                                        // response found
//                                        List requestHighlights = new ArrayList(1);
//                                        // adding highlights
//                                        requestHighlights.add(insertionPoint.getPayloadOffsets(helpers.stringToBytes(payloadsFromTextAreaActive1)));
//                                        List issues = new ArrayList(1);
//                                        issues.add(new CustomScanIssue(baseRequestResponse
//                                                .getHttpService(), this.helpers
//                                                .analyzeRequest(baseRequestResponse)
//                                                .getUrl(), new IHttpRequestResponse[]{this.callbacks
//                                                .applyMarkers(checkRequestResponseAdd, requestHighlights, matches)}, "Reflected File Download", "Submitting " + payloadsFromTextAreaActive1 + " returned the string by adding " + parametersFromTextAreaActive[i] + " parameter: " + payloadsFromTextAreaActive1
//                                                + "<br><br><b>Issue Definition</b><br><br>"
//                                                + "\"Reflected File Download(RFD) is a web attack vector that enables attackers to gain"
//                                                + " complete control over a victim ’s machine."
//                                                + "In an RFD attack, the user follows a malicious link to a trusted domain resulting in a file download from that domain."
//                                                + "computer.\""
//                                                + "<br><I>Oren Hafif</I>"
//                                                + "<br><br><b>Notes</b><br><br>"
//                                                + "\"In the absence of a filename attribute returned within a Content-Disposition "
//                                                + "response header, browsers are forced to determine the name of a downloaded file "
//                                                + "based on the URL (from the address bar). An attacker can tamper with the \"Path\" "
//                                                + "portion of the URL (between the domain name and the question mark sign \"?\") to "
//                                                + "set malicious extensions for downloads.\""
//                                                + "<br><I>Oren Hafif</I>"
//                                                + "<br><br>Sample URL: <br>https://example.com/api;/setup.bat;/setup.bat<br>"
//                                                + "<br>Sample HTML code using download attribute:<br>&#x3c;&#x61;&#x20;&#x64;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x68;&#x72;&#x65;&#x66;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x63;&#x6f;&#x6d;&#x2f;&#x61;&#x3b;&#x2f;&#x73;&#x65;&#x74;&#x75;&#x70;&#x2e;&#x62;&#x61;&#x74;&#x3b;&#x22;&#x3e;&#x44;&#x6f;&#x77;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x43;&#x6c;&#x69;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x61;&#x3e;<br>"
//                                                + "<br>Some useful urls to try from https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                                + "https://www.example-site.pt/api/search.bat?term=f00bar&callback=calc<br>"
//                                                + "https://www.example-site.pt/api/search;setup.bat?term=f00bar&callback=calc<br>"
//                                                + "https://www.example-site.pt/api/search/setup.bat?term=f00bar&callback=calc<br>"
//                                                + "https://www.example-site.pt/api/search;/setup.bat?term=f00bar&callback=calc<br>"
//                                                + "https://www.example-site.pt/api/search;/setup.bat;?term=f00bar&callback=calc<br>"
//                                                + "<br><b>References</b><br><br>"
//                                                + "https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf<br>"
//                                                + "https://www.davidsopas.com/reflected-file-download-cheat-sheet/<br>"
//                                                + "<br><br><b>Development Contact Information</b><br><br>"
//                                                + "onur.karasalihoglu@enforsec.com (@onurkarasalih) <br><br>"
//                                                + "Special thanks to Oren Hafif (@orenhafif) for the discovery of this vulnerability and support for this plugin", "High"));
//                                        // Adding issue
//                                        return issues;
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//
//        }

        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL
        // path by the same extension-provided check. The value we return from this
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

}
