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
        mainPanel.add(csrfPanel);
        mainPanel.add(headersPanel);
        mainPanel.add(clearPanel);
        add(mainPanel);

    }
}
