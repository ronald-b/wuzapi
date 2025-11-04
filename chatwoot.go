package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ChatwootConfig holds Chatwoot configuration for a user
type ChatwootConfig struct {
	Enabled     bool
	BaseURL     string
	AccountID   string
	InboxID     string
	APIToken    string
	AutoCreate  bool // Auto-create contacts if they don't exist
	SyncMedia   bool // Sync media files to Chatwoot
}

// ChatwootManager manages Chatwoot operations
type ChatwootManager struct {
	mu      sync.RWMutex
	configs map[string]*ChatwootConfig
	clients map[string]*http.Client
}

// Global Chatwoot manager instance
var chatwootManager = &ChatwootManager{
	configs: make(map[string]*ChatwootConfig),
	clients: make(map[string]*http.Client),
}

// GetChatwootManager returns the global Chatwoot manager instance
func GetChatwootManager() *ChatwootManager {
	return chatwootManager
}

// Chatwoot API Response Types
type ChatwootContact struct {
	ID              int                    `json:"id,omitempty"`
	Name            string                 `json:"name"`
	PhoneNumber     string                 `json:"phone_number,omitempty"`
	Identifier      string                 `json:"identifier,omitempty"`
	CustomAttributes map[string]interface{} `json:"custom_attributes,omitempty"`
}

type ChatwootConversation struct {
	ID               int                    `json:"id,omitempty"`
	AccountID        int                    `json:"account_id"`
	InboxID          int                    `json:"inbox_id"`
	ContactID        int                    `json:"contact_id,omitempty"`
	Status           string                 `json:"status,omitempty"`
	Messages         []ChatwootMessage      `json:"messages,omitempty"`
	CustomAttributes map[string]interface{} `json:"custom_attributes,omitempty"`
}

type ChatwootMessage struct {
	ID            int                      `json:"id,omitempty"`
	Content       string                   `json:"content"`
	MessageType   string                   `json:"message_type"`
	Private       bool                     `json:"private"`
	ContentType   string                   `json:"content_type,omitempty"`
	Attachments   []ChatwootAttachment     `json:"attachments,omitempty"`
}

type ChatwootAttachment struct {
	ID       int    `json:"id,omitempty"`
	FileType string `json:"file_type,omitempty"`
	FileURL  string `json:"data_url,omitempty"`
}

type ChatwootContactsResponse struct {
	Payload []ChatwootContact `json:"payload"`
}

type ChatwootConversationsResponse struct {
	Data struct {
		Payload []ChatwootConversation `json:"payload"`
	} `json:"data"`
}

// InitializeChatwootClient creates or updates Chatwoot client for a user
func (m *ChatwootManager) InitializeChatwootClient(userID string, config *ChatwootConfig) error {
	if !config.Enabled {
		m.RemoveClient(userID)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate configuration
	if config.BaseURL == "" || config.AccountID == "" || config.InboxID == "" || config.APIToken == "" {
		return fmt.Errorf("chatwoot configuration incomplete: baseURL, accountID, inboxID, and apiToken are required")
	}

	// Normalize BaseURL
	config.BaseURL = strings.TrimSuffix(config.BaseURL, "/")

	// Store configuration
	m.configs[userID] = config

	// Create HTTP client with timeout
	m.clients[userID] = &http.Client{
		Timeout: 30 * time.Second,
	}

	log.Info().Str("userID", userID).Msg("Chatwoot client initialized successfully")
	return nil
}

// RemoveClient removes Chatwoot client for a user
func (m *ChatwootManager) RemoveClient(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.configs, userID)
	delete(m.clients, userID)
	log.Info().Str("userID", userID).Msg("Chatwoot client removed")
}

// GetConfig returns Chatwoot configuration for a user
func (m *ChatwootManager) GetConfig(userID string) (*ChatwootConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	config, exists := m.configs[userID]
	return config, exists
}

// IsEnabled checks if Chatwoot is enabled for a user
func (m *ChatwootManager) IsEnabled(userID string) bool {
	config, exists := m.GetConfig(userID)
	return exists && config.Enabled
}

// doRequest performs an HTTP request to Chatwoot API
func (m *ChatwootManager) doRequest(userID, method, endpoint string, body interface{}) ([]byte, error) {
	m.mu.RLock()
	config, configExists := m.configs[userID]
	client, clientExists := m.clients[userID]
	m.mu.RUnlock()

	if !configExists || !clientExists {
		return nil, fmt.Errorf("chatwoot not configured for user %s", userID)
	}

	url := fmt.Sprintf("%s%s", config.BaseURL, endpoint)

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api_access_token", config.APIToken)

	log.Debug().
		Str("method", method).
		Str("url", url).
		Str("userID", userID).
		Msg("Sending request to Chatwoot")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warn().
			Int("status", resp.StatusCode).
			Str("response", string(respBody)).
			Str("url", url).
			Msg("Chatwoot API error")
		return nil, fmt.Errorf("chatwoot API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// FindOrCreateContact finds a contact by phone number or creates a new one
func (m *ChatwootManager) FindOrCreateContact(userID, phoneNumber, name string) (*ChatwootContact, error) {
	config, exists := m.GetConfig(userID)
	if !exists {
		return nil, fmt.Errorf("chatwoot not configured for user %s", userID)
	}

	// Search for existing contact
	endpoint := fmt.Sprintf("/api/v1/accounts/%s/contacts/search?q=%s", config.AccountID, phoneNumber)
	respBody, err := m.doRequest(userID, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search contact: %w", err)
	}

	var contactsResp ChatwootContactsResponse
	if err := json.Unmarshal(respBody, &contactsResp); err != nil {
		return nil, fmt.Errorf("failed to parse contacts response: %w", err)
	}

	// If contact exists, return it
	if len(contactsResp.Payload) > 0 {
		log.Debug().Str("phoneNumber", phoneNumber).Int("contactID", contactsResp.Payload[0].ID).Msg("Found existing Chatwoot contact")
		return &contactsResp.Payload[0], nil
	}

	// Create new contact if auto-create is enabled
	if !config.AutoCreate {
		return nil, fmt.Errorf("contact not found and auto-create is disabled")
	}

	contactData := map[string]interface{}{
		"name":         name,
		"phone_number": phoneNumber,
		"identifier":   phoneNumber,
	}

	endpoint = fmt.Sprintf("/api/v1/accounts/%s/contacts", config.AccountID)
	respBody, err = m.doRequest(userID, "POST", endpoint, contactData)
	if err != nil {
		return nil, fmt.Errorf("failed to create contact: %w", err)
	}

	var contact ChatwootContact
	if err := json.Unmarshal(respBody, &contact); err != nil {
		return nil, fmt.Errorf("failed to parse contact response: %w", err)
	}

	log.Info().Str("phoneNumber", phoneNumber).Int("contactID", contact.ID).Msg("Created new Chatwoot contact")
	return &contact, nil
}

// FindOrCreateConversation finds a conversation for a contact or creates a new one
func (m *ChatwootManager) FindOrCreateConversation(userID string, contactID int) (*ChatwootConversation, error) {
	config, exists := m.GetConfig(userID)
	if !exists {
		return nil, fmt.Errorf("chatwoot not configured for user %s", userID)
	}

	// Search for existing conversation
	endpoint := fmt.Sprintf("/api/v1/accounts/%s/conversations?inbox_id=%s&status=open", config.AccountID, config.InboxID)
	respBody, err := m.doRequest(userID, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search conversations: %w", err)
	}

	var convResp ChatwootConversationsResponse
	if err := json.Unmarshal(respBody, &convResp); err != nil {
		return nil, fmt.Errorf("failed to parse conversations response: %w", err)
	}

	// Find conversation for this contact
	for _, conv := range convResp.Data.Payload {
		if conv.ContactID == contactID {
			log.Debug().Int("contactID", contactID).Int("conversationID", conv.ID).Msg("Found existing Chatwoot conversation")
			return &conv, nil
		}
	}

	// Create new conversation
	convData := map[string]interface{}{
		"contact_id": contactID,
		"inbox_id":   config.InboxID,
		"status":     "open",
	}

	endpoint = fmt.Sprintf("/api/v1/accounts/%s/conversations", config.AccountID)
	respBody, err = m.doRequest(userID, "POST", endpoint, convData)
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation: %w", err)
	}

	var conversation ChatwootConversation
	if err := json.Unmarshal(respBody, &conversation); err != nil {
		return nil, fmt.Errorf("failed to parse conversation response: %w", err)
	}

	log.Info().Int("contactID", contactID).Int("conversationID", conversation.ID).Msg("Created new Chatwoot conversation")
	return &conversation, nil
}

// SendMessage sends a message to a Chatwoot conversation
func (m *ChatwootManager) SendMessage(userID string, conversationID int, content string, messageType string) error {
	config, exists := m.GetConfig(userID)
	if !exists {
		return fmt.Errorf("chatwoot not configured for user %s", userID)
	}

	messageData := map[string]interface{}{
		"content":      content,
		"message_type": messageType, // "incoming" or "outgoing"
		"private":      false,
	}

	endpoint := fmt.Sprintf("/api/v1/accounts/%s/conversations/%d/messages", config.AccountID, conversationID)
	_, err := m.doRequest(userID, "POST", endpoint, messageData)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	log.Info().Int("conversationID", conversationID).Str("type", messageType).Msg("Message sent to Chatwoot")
	return nil
}

// SyncMessageToChatwoot syncs a WhatsApp message to Chatwoot
func (m *ChatwootManager) SyncMessageToChatwoot(userID, phoneNumber, name, content string, isFromMe bool) error {
	if !m.IsEnabled(userID) {
		return nil // Silently skip if not enabled
	}

	// Find or create contact
	contact, err := m.FindOrCreateContact(userID, phoneNumber, name)
	if err != nil {
		log.Error().Err(err).Str("phoneNumber", phoneNumber).Msg("Failed to find/create Chatwoot contact")
		return err
	}

	// Find or create conversation
	conversation, err := m.FindOrCreateConversation(userID, contact.ID)
	if err != nil {
		log.Error().Err(err).Int("contactID", contact.ID).Msg("Failed to find/create Chatwoot conversation")
		return err
	}

	// Determine message type
	messageType := "incoming"
	if isFromMe {
		messageType = "outgoing"
	}

	// Send message
	if err := m.SendMessage(userID, conversation.ID, content, messageType); err != nil {
		log.Error().Err(err).Int("conversationID", conversation.ID).Msg("Failed to send message to Chatwoot")
		return err
	}

	return nil
}
