package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class CheckListPanel extends JPanel {
    public CheckListPanel() {
        // Information Gathering Label
        JPanel infoGatherPanel = new JPanel();
        infoGatherPanel.setLayout(new BoxLayout (infoGatherPanel, BoxLayout.X_AXIS));
        JLabel infoGatherLabel = new JLabel("Information Gathering");
        Font boldFont = infoGatherLabel.getFont().deriveFont(Font.BOLD, 20f);
        infoGatherLabel.setFont(boldFont);
        infoGatherPanel.add(infoGatherLabel);
        infoGatherPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Manually Explore panel
        JPanel manExplorePanel = new JPanel();
        manExplorePanel.setLayout(new BoxLayout (manExplorePanel, BoxLayout.X_AXIS));
        manExplorePanel.add(new JCheckBox());
        manExplorePanel.add(new JLabel("Manually explore the site (view source +  F12)"));
        manExplorePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Spider Panel
        JPanel spiderPanel = new JPanel();
        spiderPanel.setLayout(new BoxLayout (spiderPanel, BoxLayout.X_AXIS));
        spiderPanel.add(new JCheckBox());
        spiderPanel.add(new JLabel("Spider/crawl (Discover Content on Burp + Dirsearch) for missed or hidden content"));
        spiderPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Check for files Panel
        JPanel checkFilesPanel = new JPanel();
        checkFilesPanel.setLayout(new BoxLayout (checkFilesPanel, BoxLayout.X_AXIS));
        checkFilesPanel.add(new JCheckBox());
        checkFilesPanel.add(new JLabel("Check for files that expose content, such as robots.txt, sitemap.xml, .DS_Store, Dockerfile, zip files"));
        checkFilesPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify Tech Panel
        JPanel identifyTechPanel = new JPanel();
        identifyTechPanel.setLayout(new BoxLayout (identifyTechPanel, BoxLayout.X_AXIS));
        identifyTechPanel.add(new JCheckBox());
        identifyTechPanel.add(new JLabel("Identify used technologies (e.g., using Retire.JS + Wappalyzer)"));
        identifyTechPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify User Roles Panel
        JPanel identifyUserRolesPanel = new JPanel();
        identifyUserRolesPanel.setLayout(new BoxLayout (identifyUserRolesPanel, BoxLayout.X_AXIS));
        identifyUserRolesPanel.add(new JCheckBox());
        identifyUserRolesPanel.add(new JLabel("Identify user roles"));
        identifyUserRolesPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify Application Entry Point Panel
        JPanel identifyAppEntryPanel = new JPanel();
        identifyAppEntryPanel.setLayout(new BoxLayout (identifyAppEntryPanel, BoxLayout.X_AXIS));
        identifyAppEntryPanel.add(new JCheckBox());
        identifyAppEntryPanel.add(new JLabel("Identify application entry points"));
        identifyAppEntryPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify client-side code Panel
        JPanel identifyCsCodePanel = new JPanel();
        identifyCsCodePanel.setLayout(new BoxLayout (identifyCsCodePanel, BoxLayout.X_AXIS));
        identifyCsCodePanel.add(new JCheckBox());
        identifyCsCodePanel.add(new JLabel("Identify client-side code"));
        identifyCsCodePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify multi version Panel
        JPanel identifyMultiVerPanel = new JPanel();
        identifyMultiVerPanel.setLayout(new BoxLayout (identifyMultiVerPanel, BoxLayout.X_AXIS));
        identifyMultiVerPanel.add(new JCheckBox());
        identifyMultiVerPanel.add(new JLabel("Identify multiple versions/channels (e.g. web, mobile web, mobile app, web services)"));
        identifyMultiVerPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify co-host Panel
        JPanel identifyCoHostPanel = new JPanel();
        identifyCoHostPanel.setLayout(new BoxLayout (identifyCoHostPanel, BoxLayout.X_AXIS));
        identifyCoHostPanel.add(new JCheckBox());
        identifyCoHostPanel.add(new JLabel("Identify co-hosted and related applications"));
        identifyCoHostPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify hostname Panel
        JPanel identifyHostnamePanel = new JPanel();
        identifyHostnamePanel.setLayout(new BoxLayout (identifyHostnamePanel, BoxLayout.X_AXIS));
        identifyHostnamePanel.add(new JCheckBox());
        identifyHostnamePanel.add(new JLabel("Identify all hostnames and ports"));
        identifyHostnamePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Identify third party Panel
        JPanel identifyThirdPartyPanel = new JPanel();
        identifyThirdPartyPanel.setLayout(new BoxLayout (identifyThirdPartyPanel, BoxLayout.X_AXIS));
        identifyThirdPartyPanel.add(new JCheckBox());
        identifyThirdPartyPanel.add(new JLabel("Identify third-party hosted content"));
        identifyThirdPartyPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // If cms Panel
        JPanel ifCmsPanel = new JPanel();
        ifCmsPanel.setLayout(new BoxLayout (ifCmsPanel, BoxLayout.X_AXIS));
        ifCmsPanel.add(new JCheckBox());
        ifCmsPanel.add(new JLabel("If CMS is used check versions, CVE's, and scan using appropriate scanner (WPScan etc.)"));
        ifCmsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check cve Panel
        JPanel checkCvePanel = new JPanel();
        checkCvePanel.setLayout(new BoxLayout (checkCvePanel, BoxLayout.X_AXIS));
        checkCvePanel.add(new JCheckBox());
        checkCvePanel.add(new JLabel("Check for CVE's on the web application components + for all open ports."));
        checkCvePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Configuration Management Label
        JPanel configurationManPanel = new JPanel();
        configurationManPanel.setLayout(new BoxLayout (configurationManPanel, BoxLayout.X_AXIS));
        JLabel configManLabel = new JLabel("Configuration Management");
        configManLabel.setFont(boldFont);
        configurationManPanel.add(configManLabel);
        configurationManPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check for commonly used applications Panel
        JPanel commonAppPanel = new JPanel();
        commonAppPanel.setLayout(new BoxLayout (commonAppPanel, BoxLayout.X_AXIS));
        commonAppPanel.add(new JCheckBox());
        commonAppPanel.add(new JLabel("Check for commonly used application and administrative URLs"));
        commonAppPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check for old Panel
        JPanel checkOldPanel = new JPanel();
        checkOldPanel.setLayout(new BoxLayout (checkOldPanel, BoxLayout.X_AXIS));
        checkOldPanel.add(new JCheckBox());
        checkOldPanel.add(new JLabel("Check for old, backup and unreferenced files"));
        checkOldPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check HTTP method Panel
        JPanel checkHttpMethPanel = new JPanel();
        checkHttpMethPanel.setLayout(new BoxLayout (checkHttpMethPanel, BoxLayout.X_AXIS));
        checkHttpMethPanel.add(new JCheckBox());
        checkHttpMethPanel.add(new JLabel("Check HTTP methods supported"));
        checkHttpMethPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // file ext handling Panel
        JPanel testFileExtPanel = new JPanel();
        testFileExtPanel.setLayout(new BoxLayout (testFileExtPanel, BoxLayout.X_AXIS));
        testFileExtPanel.add(new JCheckBox());
        testFileExtPanel.add(new JLabel("Test file extensions handling"));
        testFileExtPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check cors Panel
        JPanel checkCorsPanel = new JPanel();
        checkCorsPanel.setLayout(new BoxLayout (checkCorsPanel, BoxLayout.X_AXIS));
        checkCorsPanel.add(new JCheckBox());
        checkCorsPanel.add(new JLabel("Check CORS implementation"));
        checkCorsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check headers Panel
        JPanel checkHeadersPanel = new JPanel();
        checkHeadersPanel.setLayout(new BoxLayout (checkHeadersPanel, BoxLayout.X_AXIS));
        checkHeadersPanel.add(new JCheckBox());
        checkHeadersPanel.add(new JLabel("Test for security HTTP headers (e.g. CSP, X-Frame-Options, HSTS)"));
        checkHeadersPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check for sensitive data Panel
        JPanel checkSensitiveDataPanel = new JPanel();
        checkSensitiveDataPanel.setLayout(new BoxLayout (checkSensitiveDataPanel, BoxLayout.X_AXIS));
        checkSensitiveDataPanel.add(new JCheckBox());
        checkSensitiveDataPanel.add(new JLabel("Check for sensitive data in client-side code especially .JS files (e.g. API keys, credentials)"));
        checkSensitiveDataPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Secure Transmission Label
        JPanel secureTransPanel = new JPanel();
        secureTransPanel.setLayout(new BoxLayout (secureTransPanel, BoxLayout.X_AXIS));
        JLabel secureTransLabel = new JLabel("Secure Transmission");
        secureTransLabel.setFont(boldFont);
        secureTransPanel.add(secureTransLabel);
        secureTransPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // check ssl Panel
        JPanel checkSslPanel = new JPanel();
        checkSslPanel.setLayout(new BoxLayout (checkSslPanel, BoxLayout.X_AXIS));
        checkSslPanel.add(new JCheckBox());
        checkSslPanel.add(new JLabel("Check SSL Version, Algorithms, Key length"));
        checkSslPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Headers Panel
        JPanel headersPanel = new JPanel();
        headersPanel.setLayout(new BoxLayout (headersPanel, BoxLayout.X_AXIS));
        headersPanel.add(new JLabel("headers label"));
        headersPanel.add(new JLabel("  "));
        JTextField checkListTextField = new JTextField("Text Field");
        checkListTextField.setPreferredSize(new Dimension(200,30));
        checkListTextField.setMaximumSize(checkListTextField.getPreferredSize());
        headersPanel.add(checkListTextField);
        headersPanel.add(new JLabel("  "));
        JButton go = new JButton("GO");
        headersPanel.add(go);
        go.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                checkListTextField.setText("GO Button Clicked");
            }
        });

        // Clear panel
        JPanel clearPanel = new JPanel();
        clearPanel.setLayout(new BoxLayout (clearPanel, BoxLayout.X_AXIS));
        JButton clearButtonForKeyHacks = new JButton("Clear");
        clearPanel.add(clearButtonForKeyHacks);
        // clear button action
        clearButtonForKeyHacks.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                checkListTextField.setText(null);
            }
        });

        // Main JPanel
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout (mainPanel, BoxLayout.Y_AXIS));
        mainPanel.add(infoGatherPanel);
        mainPanel.add(manExplorePanel);
        mainPanel.add(spiderPanel);
        mainPanel.add(checkFilesPanel);
        mainPanel.add(identifyTechPanel);
        mainPanel.add(identifyUserRolesPanel);
        mainPanel.add(identifyAppEntryPanel);
        mainPanel.add(identifyCsCodePanel);
        mainPanel.add(identifyMultiVerPanel);
        mainPanel.add(identifyCoHostPanel);
        mainPanel.add(identifyHostnamePanel);
        mainPanel.add(identifyThirdPartyPanel);
        mainPanel.add(ifCmsPanel);
        mainPanel.add(checkCvePanel);
        mainPanel.add(configManLabel);
        mainPanel.add(commonAppPanel);
        mainPanel.add(checkOldPanel);
        mainPanel.add(checkHttpMethPanel);
        mainPanel.add(testFileExtPanel);
        mainPanel.add(checkCorsPanel);
        mainPanel.add(checkHeadersPanel);
        mainPanel.add(checkSensitiveDataPanel);
        mainPanel.add(secureTransPanel);
        mainPanel.add(checkSslPanel);
        mainPanel.add(headersPanel);
        mainPanel.add(clearPanel);
        add(mainPanel);

    }
}
