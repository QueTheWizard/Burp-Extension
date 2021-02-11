package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class CheckListPanel extends JPanel {
    public CheckListPanel() {
        // CSRF panel
        JPanel csrfPanel = new JPanel();
        csrfPanel.setLayout(new BoxLayout (csrfPanel, BoxLayout.X_AXIS));
        csrfPanel.add(new JLabel("csrf label"));
        csrfPanel.add(new JCheckBox());
//        add(csrfPanel);

        // Headers Panel
        JPanel headersPanel = new JPanel();
        headersPanel.setLayout(new BoxLayout (headersPanel, BoxLayout.X_AXIS));
        headersPanel.add(new JLabel("headers label"));
        JTextField checkListTextField = new JTextField("Text Field");
        checkListTextField.setPreferredSize(new Dimension(200,30));
        checkListTextField.setMaximumSize(checkListTextField.getPreferredSize());
        headersPanel.add(checkListTextField);
        JButton go = new JButton("GO");
        headersPanel.add(go);
//        add(headersPanel);

        JPanel clearPanel = new JPanel();
        clearPanel.setLayout(new BoxLayout (clearPanel, BoxLayout.X_AXIS));
        JButton clearButtonForKeyHacks = new JButton("Clear");
        clearPanel.add(clearButtonForKeyHacks);
//        add(clearPanel);
        clearButtonForKeyHacks.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                checkListTextField.setText(null);
            }
        });

        // Main JPanel
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout (mainPanel, BoxLayout.Y_AXIS));
        mainPanel.add(csrfPanel);
        mainPanel.add(headersPanel);
        mainPanel.add(clearPanel);
        add(mainPanel);

        //checkListPanel.add(apiKeyCheckButton);
//        checkListPanel.add(checkListPanel);
//        apiKeyCheckButton.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
////                        GET Request to check the API key
////                        https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY_HERE
//            }
//        });
    }
    }
