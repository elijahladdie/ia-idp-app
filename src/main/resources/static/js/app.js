// Admin Console JavaScript
class AdminConsole {
    constructor() {
        this.baseUrl = window.location.origin;
        this.apiUrl = `${this.baseUrl}/admin`;
        this.init();
    }

    init() {
        this.setActiveNavigation();
        this.setupEventListeners();
        this.loadUserInfo();
    }

    // Set active navigation item based on current page
    setActiveNavigation() {
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.navbar-nav a');
        
        navLinks.forEach(link => {
            link.classList.remove('active');
            const href = link.getAttribute('href');
            
            // Handle different path patterns
            if (currentPath === '/ui/console/' && href === '/ui/console/') {
                link.classList.add('active');
            } else if (currentPath.endsWith(href.split('/').pop())) {
                link.classList.add('active');
            }
        });
    }

    // Setup common event listeners
    setupEventListeners() {
        // Handle form submissions
        const forms = document.querySelectorAll('form[data-api]');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => this.handleFormSubmit(e));
        });

        // Handle delete buttons
        const deleteButtons = document.querySelectorAll('[data-action="delete"]');
        deleteButtons.forEach(button => {
            button.addEventListener('click', (e) => this.handleDelete(e));
        });
    }

    // Generic form submission handler
    async handleFormSubmit(event) {
        event.preventDefault();
        const form = event.target;
        const endpoint = form.dataset.api;
        const method = form.dataset.method || 'POST';
        
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        
        // Convert comma-separated values to arrays
        if (data.redirectUris) {
            data.redirectUris = data.redirectUris.split(',').map(uri => uri.trim()).filter(uri => uri);
        }
        if (data.grantTypes) {
            data.grantTypes = data.grantTypes.split(',').map(type => type.trim()).filter(type => type);
        }

        try {
            this.showLoading(form);
            const response = await this.apiRequest(endpoint, method, data);
            this.handleFormSuccess(form, response);
        } catch (error) {
            this.handleFormError(form, error);
        } finally {
            this.hideLoading(form);
        }
    }

    // Generic delete handler
    async handleDelete(event) {
        event.preventDefault();
        const button = event.target;
        const endpoint = button.dataset.endpoint;
        const confirmMessage = button.dataset.confirm || 'Are you sure you want to delete this item?';
        
        if (!confirm(confirmMessage)) {
            return;
        }

        try {
            this.showLoading(button);
            await this.apiRequest(endpoint, 'DELETE');
            this.handleDeleteSuccess(button);
        } catch (error) {
            this.handleDeleteError(button, error);
        } finally {
            this.hideLoading(button);
        }
    }

    // API request wrapper with automatic token handling
    async apiRequest(endpoint, method = 'GET', data = null) {
        const url = `${this.apiUrl}${endpoint}`;
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        // Get JWT token from session
        try {
            const tokenResponse = await fetch('/admin/session/token', {
                credentials: 'same-origin'
            });
            
            if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.access_token) {
                    options.headers['Authorization'] = `${tokenData.token_type || 'Bearer'} ${tokenData.access_token}`;
                }
            }
        } catch (error) {
            console.warn('Failed to get session token:', error);
        }

        if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);
        
        if (!response.ok) {
            // Handle authentication errors
            if (response.status === 401) {
                this.handleAuthenticationError();
                throw new Error('Authentication required. Please log in again.');
            }
            
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        
        return await response.text();
    }

    // Handle authentication errors
    handleAuthenticationError() {
        this.showAlert('error', 'Session expired. Redirecting to login...');
        setTimeout(() => {
            window.location.href = '/login.html';
        }, 2000);
    }

    // Load and display user information from session
    async loadUserInfo() {
        try {
            const response = await fetch('/admin/session/info', {
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                const userInfo = await response.json();
                this.displayUserInfo(userInfo);
            }
        } catch (error) {
            console.warn('Failed to load user info:', error);
        }
    }

    // Display user information in the UI
    displayUserInfo(userInfo) {
        // Update user name in navigation if element exists
        const userNameElement = document.querySelector('.user-name');
        if (userNameElement && userInfo.user_name) {
            userNameElement.textContent = userInfo.user_name;
        }

        // Update user email if element exists
        const userEmailElement = document.querySelector('.user-email');
        if (userEmailElement && userInfo.user_email) {
            userEmailElement.textContent = userInfo.user_email;
        }

        // Store user info globally for other components
        window.currentUser = userInfo;
    }

    // Register new OAuth client
    async registerClient(clientData) {
        return await this.apiRequest('/clients', 'POST', clientData);
    }

    // Get all OAuth clients
    async getClients() {
        return await this.apiRequest('/clients', 'GET');
    }

    // Get specific OAuth client
    async getClient(clientId) {
        return await this.apiRequest(`/clients/${clientId}`, 'GET');
    }

    // Update OAuth client
    async updateClient(clientId, clientData) {
        return await this.apiRequest(`/clients/${clientId}`, 'PUT', clientData);
    }

    // Delete OAuth client
    async deleteClient(clientId) {
        return await this.apiRequest(`/clients/${clientId}`, 'DELETE');
    }

    // Get configuration
    async getConfig() {
        return await this.apiRequest('/config', 'GET');
    }

    // Update configuration
    async updateConfig(configData) {
        return await this.apiRequest('/config', 'POST', configData);
    }

    // Show loading state
    showLoading(element) {
        const button = element.querySelector('button[type="submit"]') || element;
        const originalText = button.textContent;
        button.dataset.originalText = originalText;
        button.innerHTML = '<span class="spinner"></span>Loading...';
        button.disabled = true;
    }

    // Hide loading state
    hideLoading(element) {
        const button = element.querySelector('button[type="submit"]') || element;
        const originalText = button.dataset.originalText;
        if (originalText) {
            button.textContent = originalText;
            delete button.dataset.originalText;
        }
        button.disabled = false;
    }

    // Handle form success
    handleFormSuccess(form, response) {
        this.clearErrors(form);
        
        // Show success message
        this.showAlert('success', 'Operation completed successfully!');
        
        // Handle specific success cases
        if (form.id === 'registerForm' && response.clientId) {
            this.showClientCredentials(response);
        }
        
        // Reset form if not editing
        if (!form.dataset.editing) {
            form.reset();
        }
        
        // Reload data if on list page
        if (typeof window.loadClients === 'function') {
            window.loadClients();
        }
    }

    // Handle form error
    handleFormError(form, error) {
        this.clearErrors(form);
        this.showAlert('error', error.message);
        
        // Highlight form fields with errors if error details are provided
        if (error.details && typeof error.details === 'object') {
            Object.keys(error.details).forEach(field => {
                const input = form.querySelector(`[name="${field}"]`);
                if (input) {
                    input.classList.add('error');
                }
            });
        }
    }

    // Handle delete success
    handleDeleteSuccess(button) {
        this.showAlert('success', 'Item deleted successfully!');
        
        // Remove row from table or redirect
        const row = button.closest('tr');
        if (row) {
            row.remove();
        } else {
            // Redirect to list page
            window.location.href = 'clients.html';
        }
    }

    // Handle delete error
    handleDeleteError(button, error) {
        this.showAlert('error', `Failed to delete: ${error.message}`);
    }

    // Show client credentials after registration
    showClientCredentials(client) {
        const container = document.getElementById('clientCredentials');
        if (container) {
            container.innerHTML = `
                <div class="alert alert-success">
                    <h3>Client Registered Successfully!</h3>
                    <p><strong>Client ID:</strong> <code>${client.clientId}</code></p>
                    <p><strong>Client Secret:</strong> <code>${client.clientSecret}</code></p>
                    <p class="mt-2"><strong>Important:</strong> Please save the client secret now. It will not be shown again for security reasons.</p>
                </div>
            `;
            container.classList.remove('hidden');
        }
    }

    // Show alert message
    showAlert(type, message) {
        // Remove existing alerts
        const existingAlerts = document.querySelectorAll('.alert');
        existingAlerts.forEach(alert => alert.remove());
        
        // Create new alert
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        
        // Insert at top of main content
        const main = document.querySelector('main') || document.querySelector('.container');
        if (main) {
            main.insertBefore(alert, main.firstChild);
        }
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 5000);
    }

    // Clear form errors
    clearErrors(form) {
        const errorInputs = form.querySelectorAll('.error');
        errorInputs.forEach(input => input.classList.remove('error'));
    }

    // Utility: Get URL parameter
    getUrlParameter(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }

    // Utility: Format date
    formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    // Utility: Truncate text
    truncateText(text, maxLength = 50) {
        if (!text || text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    // Load and render clients table
    async loadAndRenderClients() {
        try {
            const clients = await this.getClients();
            this.renderClientsTable(clients);
        } catch (error) {
            this.showAlert('error', `Failed to load clients: ${error.message}`);
        }
    }

    // Render clients table
    renderClientsTable(clients) {
        const tbody = document.querySelector('#clientsTable tbody');
        if (!tbody) return;

        if (!clients || clients.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No clients found</td></tr>';
            return;
        }

        tbody.innerHTML = clients.map(client => `
            <tr>
                <td><code>${client.clientId}</code></td>
                <td>${client.clientName || 'Unnamed Client'}</td>
                <td>
                    <span class="badge ${client.active ? 'badge-success' : 'badge-danger'}">
                        ${client.active ? 'Yes' : 'No'}
                    </span>
                </td>
                <td>
                    <div class="d-flex gap-1">
                        <a href="client.html?id=${client.clientId}" class="btn btn-primary btn-sm">View</a>
                        <button type="button" class="btn btn-danger btn-sm" 
                                data-action="delete" 
                                data-endpoint="/clients/${client.clientId}"
                                data-confirm="Are you sure you want to delete this client?">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        // Re-setup event listeners for new buttons
        this.setupEventListeners();
    }

    // Load and render client details
    async loadAndRenderClientDetails(clientId) {
        try {
            const client = await this.getClient(clientId);
            this.renderClientDetails(client);
        } catch (error) {
            this.showAlert('error', `Failed to load client details: ${error.message}`);
        }
    }

    // Render client details
    renderClientDetails(client) {
        const container = document.getElementById('clientDetails');
        if (!container) return;

        container.innerHTML = `
            <div class="card">
                <h2>Client Details</h2>
                <div class="form-group">
                    <label>Client ID:</label>
                    <code>${client.clientId}</code>
                </div>
                <div class="form-group">
                    <label>Client Name:</label>
                    <span>${client.clientName || 'Unnamed Client'}</span>
                </div>
                <div class="form-group">
                    <label>Redirect URIs:</label>
                    <span>${client.redirectUris ? client.redirectUris.join(', ') : 'None'}</span>
                </div>
                <div class="form-group">
                    <label>Grant Types:</label>
                    <span>${client.grantTypes ? client.grantTypes.join(', ') : 'None'}</span>
                </div>
                <div class="form-group">
                    <label>Active Status:</label>
                    <span class="badge ${client.active ? 'badge-success' : 'badge-danger'}">
                        ${client.active ? 'Active' : 'Inactive'}
                    </span>
                </div>
                <div class="form-group">
                    <label>Created At:</label>
                    <span>${this.formatDate(client.createdAt)}</span>
                </div>
                <div class="d-flex gap-2 mt-3">
                    <button type="button" class="btn btn-primary" onclick="toggleEditMode()">Edit</button>
                    <button type="button" class="btn btn-danger" 
                            data-action="delete" 
                            data-endpoint="/clients/${client.clientId}"
                            data-confirm="Are you sure you want to delete this client? This action cannot be undone.">
                        Delete Client
                    </button>
                </div>
            </div>
            
            <div id="editForm" class="card hidden">
                <h3>Edit Client</h3>
                <form data-api="/clients/${client.clientId}" data-method="PUT" data-editing="true">
                    <div class="form-group">
                        <label for="clientName">Client Name:</label>
                        <input type="text" id="clientName" name="clientName" class="form-control" 
                               value="${client.clientName || ''}" required>
                    </div>
                    <div class="form-group">
                        <label for="redirectUris">Redirect URIs (comma-separated):</label>
                        <textarea id="redirectUris" name="redirectUris" class="form-control"
                                  placeholder="https://example.com/callback, https://app.example.com/auth">${client.redirectUris ? client.redirectUris.join(', ') : ''}</textarea>
                    </div>
                    <div class="form-group">
                        <label for="grantTypes">Grant Types (comma-separated):</label>
                        <input type="text" id="grantTypes" name="grantTypes" class="form-control" 
                               value="${client.grantTypes ? client.grantTypes.join(', ') : ''}" required>
                    </div>
                    <div class="form-group">
                        <label for="active">Active:</label>
                        <select id="active" name="active" class="form-control">
                            <option value="true" ${client.active ? 'selected' : ''}>Active</option>
                            <option value="false" ${!client.active ? 'selected' : ''}>Inactive</option>
                        </select>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-success">Save Changes</button>
                        <button type="button" class="btn btn-secondary" onclick="toggleEditMode()">Cancel</button>
                    </div>
                </form>
            </div>
        `;

        // Re-setup event listeners
        this.setupEventListeners();
    }

    // Load and render configuration
    async loadAndRenderConfig() {
        try {
            const config = await this.getConfig();
            this.renderConfig(config);
        } catch (error) {
            this.showAlert('error', `Failed to load configuration: ${error.message}`);
        }
    }

    // Render configuration form
    renderConfig(config) {
        const form = document.getElementById('configForm');
        if (!form) return;

        const baseUrlInput = form.querySelector('[name="baseUrl"]');
        const issuerInput = form.querySelector('[name="issuer"]');
        const jwksUriInput = form.querySelector('[name="jwksUri"]');

        if (baseUrlInput) baseUrlInput.value = config.baseUrl || '';
        if (issuerInput) issuerInput.value = config.issuer || '';
        if (jwksUriInput) jwksUriInput.value = config.jwksUri || '';
    }
}

// Initialize admin console when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminConsole = new AdminConsole();
});

// Global functions for inline event handlers
function toggleEditMode() {
    const details = document.getElementById('clientDetails');
    const editForm = document.getElementById('editForm');
    
    if (details && editForm) {
        details.classList.toggle('hidden');
        editForm.classList.toggle('hidden');
    }
}

// Page-specific load functions
function loadClients() {
    if (window.adminConsole) {
        window.adminConsole.loadAndRenderClients();
    }
}

function loadClientDetails() {
    const clientId = window.adminConsole?.getUrlParameter('id');
    if (clientId && window.adminConsole) {
        window.adminConsole.loadAndRenderClientDetails(clientId);
    }
}

function loadConfig() {
    if (window.adminConsole) {
        window.adminConsole.loadAndRenderConfig();
    }
}
