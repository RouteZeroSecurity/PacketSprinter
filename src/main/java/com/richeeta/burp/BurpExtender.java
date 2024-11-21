/*
 * PacketSprinter - Burp Suite Extension
 * Author: Richard Hyunho Im (@richeeta) at Route Zero Security (https://routezero.security)
 * 
 * Implementation of HTTP/2 single-packet attack for race condition testing. Based on research by James Kettle.
 */

package com.richeeta.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

public class BurpExtender implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private List<HttpRequest> duplicatedRequests;
    private List<ResponseData> responses;
    private JPanel mainPanel;
    private JSplitPane splitPane;
    private JPanel requestsPanel;
    private JPanel responsesPanel;
    private JTextArea[] requestEditors;
    private JTextPane[] responseEditors;
    private JComboBox<String> httpVersionCombo;
    private static final String HTTP2 = "HTTP/2 (Single-packet)";
    
    private static final int ROW_HEIGHT = 300;
    private static final int MIN_WIDTH = 400;
    private static final int PANEL_SPACING = 10;
    
    private static final SimpleAttributeSet NORMAL_STYLE = new SimpleAttributeSet();
    private static final SimpleAttributeSet HIGHLIGHT_STYLE = new SimpleAttributeSet();
    private static final SimpleAttributeSet HEADER_STYLE = new SimpleAttributeSet();
    
    static {
        StyleConstants.setBackground(HIGHLIGHT_STYLE, new Color(255, 255, 200));
        StyleConstants.setBold(HEADER_STYLE, true);
        StyleConstants.setForeground(HEADER_STYLE, new Color(0, 102, 204));
    }

    private static class ResponseData {
        String rawResponse;
        int statusCode;
        Map<String, String> headers;
        String body;
        long timing;
        long bodyLength;
        
        ResponseData() {
            this.headers = new HashMap<>();
            this.rawResponse = "";
            this.body = "";
            this.statusCode = 0;
            this.timing = 0;
            this.bodyLength = 0;
        }
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.duplicatedRequests = new ArrayList<>();
        this.responses = new ArrayList<>();

        api.extension().setName("PacketSprinter: Send Requests in Parallel");
        api.userInterface().registerContextMenuItemsProvider(this);
        
        initializeUI();
        api.userInterface().registerSuiteTab("PacketSprinter", mainPanel);
    }

private void sendParallelRequests() {
    if (duplicatedRequests.isEmpty()) {
        JOptionPane.showMessageDialog(null, "No requests to send.");
        return;
    }

    SwingUtilities.invokeLater(() -> {
        for (JTextPane editor : responseEditors) {
            editor.setText("Preparing to send request...");
        }
    });

    // Run requests in a separate thread
    new Thread(() -> {
        try {
            // Prepare requests with optimized headers for HTTP/2
            List<HttpRequest> optimizedRequests = duplicatedRequests.stream()
                .map(request -> request
                    .withRemovedHeader("Connection") // HTTP/2 handles this implicitly
                    .withRemovedHeader("Accept-Encoding") // Ensure no compression issues
                    .withHeader("Accept-Encoding", "identity") // Avoid transformations
                    .withHeader("Cache-Control", "no-cache") // Ensure fresh content
                )
                .toList();

            long startTime = System.nanoTime();

            // Send requests in parallel using HTTP/2 mode
            List<HttpRequestResponse> results = api.http().sendRequests(optimizedRequests, HttpMode.HTTP_2);

            long endTime = System.nanoTime();

            // Process responses
            final List<ResponseData> processedResponses = results.stream()
                .map(result -> processResponse(result, endTime - startTime))
                .toList();

            // Update UI in EDT
            SwingUtilities.invokeLater(() -> {
                responses.clear();
                responses.addAll(processedResponses);

                for (int i = 0; i < responses.size(); i++) {
                    updateResponseDisplay(responseEditors[i], responses.get(i), i);
                }

                logTimingAnalysis(responses);
            });

        } catch (Exception e) {
            api.logging().logToError("Error sending parallel requests: " + e.getMessage());
            SwingUtilities.invokeLater(() -> 
                JOptionPane.showMessageDialog(null, "Error sending requests: " + e.getMessage())
            );
        }
    }, "PacketSprinter-RequestThread").start();
}


    private ResponseData processResponse(HttpRequestResponse reqRes, long nanoTime) {
        ResponseData responseData = new ResponseData();
        responseData.timing = nanoTime / 1_000_000; // Convert to milliseconds

        if (reqRes != null && reqRes.response() != null) {
            HttpResponse response = reqRes.response();
            responseData.statusCode = response.statusCode();
            responseData.bodyLength = response.body().length();
            responseData.body = response.bodyToString();
            response.headers().forEach(header -> 
                responseData.headers.put(header.name(), header.value()));
            responseData.rawResponse = response.toString();
        } else {
            responseData.statusCode = -1;
            responseData.body = "No response received";
        }

        return responseData;
    }

    private void logTimingAnalysis(List<ResponseData> responses) {
        if (responses.isEmpty()) return;

        StringBuilder analysis = new StringBuilder("\nRequest Analysis:\n");
        analysis.append(String.format("Total Requests Sent: %d\n", responses.size()));
        
        // Analyze status codes
        Map<Integer, Long> statusCounts = responses.stream()
            .collect(Collectors.groupingBy(r -> r.statusCode, Collectors.counting()));
        analysis.append("\nStatus Code Distribution:\n");
        statusCounts.forEach((code, count) -> 
            analysis.append(String.format("HTTP %d: %d requests\n", code, count)));

        // Analyze response lengths
        DoubleSummaryStatistics lengthStats = responses.stream()
            .mapToDouble(r -> r.bodyLength)
            .summaryStatistics();
        analysis.append(String.format("\nResponse Length Analysis:\n"));
        analysis.append(String.format("Min: %d bytes\n", (long)lengthStats.getMin()));
        analysis.append(String.format("Max: %d bytes\n", (long)lengthStats.getMax()));
        analysis.append(String.format("Average: %.2f bytes\n", lengthStats.getAverage()));

        api.logging().logToOutput(analysis.toString());
    }

private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(PANEL_SPACING, PANEL_SPACING));
        mainPanel.setBorder(new EmptyBorder(PANEL_SPACING, PANEL_SPACING, PANEL_SPACING, PANEL_SPACING));

        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        
        requestsPanel = new JPanel();
        responsesPanel = new JPanel();
        requestsPanel.setLayout(new BoxLayout(requestsPanel, BoxLayout.Y_AXIS));
        responsesPanel.setLayout(new BoxLayout(responsesPanel, BoxLayout.Y_AXIS));
        
        JScrollPane requestScrollPane = new JScrollPane(requestsPanel);
        JScrollPane responseScrollPane = new JScrollPane(responsesPanel);
        requestScrollPane.setMinimumSize(new Dimension(MIN_WIDTH, ROW_HEIGHT));
        responseScrollPane.setMinimumSize(new Dimension(MIN_WIDTH, ROW_HEIGHT));
        
        splitPane.setLeftComponent(requestScrollPane);
        splitPane.setRightComponent(responseScrollPane);

        // Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        httpVersionCombo = new JComboBox<>(new String[]{HTTP2});
        JLabel versionLabel = new JLabel("HTTP Version: ");
        
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(1, 1, 100, 1);
        JSpinner duplicatesSpinner = new JSpinner(spinnerModel);
        JLabel spinnerLabel = new JLabel("Number of duplicates: ");
        
        JButton duplicateButton = new JButton("Duplicate Request");
        JButton sendButton = new JButton("Send All Requests");
        JButton clearButton = new JButton("Clear Requests");

        duplicateButton.addActionListener(e -> {
            int count = (Integer) duplicatesSpinner.getValue();
            for (int i = 0; i < count; i++) {
                duplicateRequest();
            }
        });
        
        sendButton.addActionListener(e -> sendParallelRequests());
        clearButton.addActionListener(e -> clearRequests());

        controlPanel.add(versionLabel);
        controlPanel.add(httpVersionCombo);
        controlPanel.add(Box.createHorizontalStrut(PANEL_SPACING));
        controlPanel.add(spinnerLabel);
        controlPanel.add(duplicatesSpinner);
        controlPanel.add(Box.createHorizontalStrut(PANEL_SPACING));
        controlPanel.add(duplicateButton);
        controlPanel.add(sendButton);
        controlPanel.add(clearButton);

        mainPanel.add(splitPane, BorderLayout.CENTER);
        mainPanel.add(controlPanel, BorderLayout.SOUTH);
        
        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
    }

    private void updateUI() {
        requestsPanel.removeAll();
        responsesPanel.removeAll();

        requestEditors = new JTextArea[duplicatedRequests.size()];
        responseEditors = new JTextPane[duplicatedRequests.size()];

        for (int i = 0; i < duplicatedRequests.size(); i++) {
            // Request Panel
            JPanel singleRequestPanel = new JPanel(new BorderLayout());
            singleRequestPanel.setBorder(BorderFactory.createTitledBorder("Request " + (i + 1)));
            
            Dimension panelSize = new Dimension(MIN_WIDTH, ROW_HEIGHT);
            singleRequestPanel.setMinimumSize(panelSize);
            singleRequestPanel.setPreferredSize(panelSize);
            
            JTextArea requestEditor = new JTextArea(duplicatedRequests.get(i).toString());
            requestEditor.setLineWrap(true);
            requestEditor.setWrapStyleWord(true);
            requestEditors[i] = requestEditor;
            
            JScrollPane requestScroll = new JScrollPane(requestEditor);
            singleRequestPanel.add(requestScroll);

            // Response Panel
            JPanel singleResponsePanel = new JPanel(new BorderLayout());
            singleResponsePanel.setBorder(BorderFactory.createTitledBorder("Response " + (i + 1)));
            singleResponsePanel.setMinimumSize(panelSize);
            singleResponsePanel.setPreferredSize(panelSize);
            
            JTextPane responseEditor = new JTextPane();
            responseEditor.setEditable(false);
            responseEditors[i] = responseEditor;
            
            if (i < responses.size() && responses.get(i) != null) {
                updateResponseDisplay(responseEditor, responses.get(i), i);
            }
            
            JScrollPane responseScroll = new JScrollPane(responseEditor);
            singleResponsePanel.add(responseScroll);

            if (i > 0) {
                requestsPanel.add(Box.createRigidArea(new Dimension(0, PANEL_SPACING)));
                responsesPanel.add(Box.createRigidArea(new Dimension(0, PANEL_SPACING)));
            }

            requestsPanel.add(singleRequestPanel);
            responsesPanel.add(singleResponsePanel);
        }

        mainPanel.revalidate();
        mainPanel.repaint();
    }

    private void updateResponseDisplay(JTextPane editor, ResponseData response, int index) {
        StyledDocument doc = editor.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            
            insertText(doc, "Request timing: " + response.timing + "ms\n", HEADER_STYLE);
            
            String statusText = "Status Code: " + response.statusCode + "\n";
            insertText(doc, statusText, 
                shouldHighlight("status", index) ? HIGHLIGHT_STYLE : NORMAL_STYLE);
            
            String lengthText = "Body Length: " + response.bodyLength + "\n";
            insertText(doc, lengthText,
                shouldHighlight("length", index) ? HIGHLIGHT_STYLE : NORMAL_STYLE);

            if (!response.headers.isEmpty()) {
                insertText(doc, "\nHeaders:\n", HEADER_STYLE);
                for (Map.Entry<String, String> header : response.headers.entrySet()) {
                    String headerText = header.getKey() + ": " + header.getValue() + "\n";
                    insertText(doc, headerText,
                        shouldHighlight("header:" + header.getKey(), index) ? HIGHLIGHT_STYLE : NORMAL_STYLE);
                }
            }
            
            if (response.body != null && !response.body.isEmpty()) {
                insertText(doc, "\nBody:\n", HEADER_STYLE);
                insertText(doc, response.body,
                    shouldHighlight("body", index) ? HIGHLIGHT_STYLE : NORMAL_STYLE);
            }
            
        } catch (BadLocationException e) {
            api.logging().logToError("Error updating response display: " + e.getMessage());
        }
    }

    private void insertText(StyledDocument doc, String text, AttributeSet style) throws BadLocationException {
        doc.insertString(doc.getLength(), text, style);
    }

    private boolean shouldHighlight(String component, int index) {
        if (index == 0 || responses.size() <= 1) return false;
        
        ResponseData baseResponse = responses.get(0);
        ResponseData currentResponse = responses.get(index);
        
        return switch (component) {
            case "status" -> baseResponse.statusCode != currentResponse.statusCode;
            case "length" -> baseResponse.bodyLength != currentResponse.bodyLength;
            case "body" -> !Objects.equals(baseResponse.body, currentResponse.body);
            default -> {
                if (component.startsWith("header:")) {
                    String headerName = component.substring(7);
                    String baseValue = baseResponse.headers.get(headerName);
                    String currentValue = currentResponse.headers.get(headerName);
                    yield !Objects.equals(baseValue, currentValue);
                }
                yield false;
            }
        };
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        if (event.isFromTool(ToolType.PROXY) || event.isFromTool(ToolType.REPEATER)) {
            JMenuItem menuItem = new JMenuItem("Send Requests in Single Packet");
            menuItem.addActionListener(e -> handleRequest(event));
            menuItems.add(menuItem);
        }
        return menuItems;
    }

    private void handleRequest(ContextMenuEvent event) {
        List<HttpRequestResponse> selectedRequests = event.selectedRequestResponses();
        if (selectedRequests != null && !selectedRequests.isEmpty()) {
            HttpRequest baseRequest = selectedRequests.get(0).request();
            
            // Update collections in EDT
            SwingUtilities.invokeLater(() -> {
                duplicatedRequests.clear();
                responses.clear();
                duplicatedRequests.add(baseRequest);
                responses.add(new ResponseData());
                updateUI();
                JOptionPane.showMessageDialog(null, "Request loaded. Go to the 'PacketSprinter' tab.");
            });
        }
    }

    private void duplicateRequest() {
        if (!duplicatedRequests.isEmpty()) {
            HttpRequest lastRequest = duplicatedRequests.get(duplicatedRequests.size() - 1);
            
            // Update collections in EDT
            SwingUtilities.invokeLater(() -> {
                duplicatedRequests.add(HttpRequest.httpRequest(
                    lastRequest.httpService(),
                    lastRequest.toByteArray()
                ));
                responses.add(new ResponseData());
                updateUI();
            });
        } else {
            SwingUtilities.invokeLater(() -> 
                JOptionPane.showMessageDialog(null, "No base request loaded to duplicate.")
            );
        }
    }

    private void clearRequests() {
        SwingUtilities.invokeLater(() -> {
            duplicatedRequests.clear();
            responses.clear();
            updateUI();
        });
    }

    @Override
    public void extensionUnloaded() {
        clearRequests();
    }
}