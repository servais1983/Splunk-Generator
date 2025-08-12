// Splunk SPL Command Generator - Main JavaScript

class SPLGenerator {
    constructor() {
        this.initializeEventListeners();
        this.templates = this.initializeTemplates();
        this.setupCustomInputs();
        this.initializeTheme();
        this.loadAutoSave();
    }

    initializeEventListeners() {
        // Generate command button
        document.getElementById('generateCommand').addEventListener('click', () => {
            this.generateSPLCommand();
        });

        // Copy command button
        document.getElementById('copyCommand').addEventListener('click', () => {
            this.copyToClipboard();
        });

        // Clear command button
        document.getElementById('clearCommand').addEventListener('click', () => {
            this.clearCommand();
        });

        // Add filter button
        document.getElementById('addFilter').addEventListener('click', () => {
            this.addFilterRow();
        });

        // Remove filter buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-filter')) {
                this.removeFilterRow(e.target);
            }
        });

        // Template buttons
        document.querySelectorAll('.template-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.loadTemplate(e.target.dataset.template);
            });
        });

        // Search command change
        document.getElementById('searchCommand').addEventListener('change', (e) => {
            this.handleSearchCommandChange(e.target.value);
        });

        // Custom index/sourcetype handling
        document.getElementById('indexSelect').addEventListener('change', (e) => {
            this.handleCustomInput(e.target, 'index');
        });

        document.getElementById('sourcetypeSelect').addEventListener('change', (e) => {
            this.handleCustomInput(e.target, 'sourcetype');
        });

        // Filter field change
        document.addEventListener('change', (e) => {
            if (e.target.classList.contains('filter-field')) {
                this.handleCustomInput(e.target, 'filter-field');
            }
        });

        // Group by field change
        document.getElementById('groupByField').addEventListener('change', (e) => {
            this.handleCustomInput(e.target, 'groupBy');
        });

        // Theme toggle
        document.getElementById('themeToggle').addEventListener('click', () => {
            this.toggleTheme();
        });

        // Save/Load configuration
        document.getElementById('saveConfig').addEventListener('click', () => {
            this.saveConfiguration();
        });

        document.getElementById('loadConfig').addEventListener('click', () => {
            this.loadConfiguration();
        });

        // History and Help
        document.getElementById('showHistory').addEventListener('click', () => {
            this.showHistory();
        });

        document.getElementById('showHelp').addEventListener('click', () => {
            this.showHelp();
        });

        // Clear history
        document.getElementById('clearHistory').addEventListener('click', () => {
            this.clearHistory();
        });

        // Time range change
        document.getElementById('timeRange').addEventListener('change', (e) => {
            this.handleTimeRangeChange(e.target.value);
        });

        // Quick time buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('quick-time')) {
                this.setQuickTime(e.target.dataset.time);
            }
        });

        // Auto-save on input changes
        this.setupAutoSave();

        // Auto-completion
        this.setupAutoCompletion();

        // Drag and drop for filters
        this.setupDragAndDrop();

        // Real-time validation
        this.setupRealTimeValidation();
    }

    setupCustomInputs() {
        // Setup custom input handling for various fields
        this.customInputs = new Map();
    }

    handleCustomInput(selectElement, type) {
        if (selectElement.value === 'custom') {
            const customValue = prompt(`Enter custom ${type}:`);
            if (customValue && customValue.trim()) {
                this.customInputs.set(`${type}-${selectElement.id || selectElement.className}`, customValue.trim());
                selectElement.value = customValue.trim();
            } else {
                selectElement.value = '';
            }
        }
    }

    handleSearchCommandChange(command) {
        const statsSection = document.getElementById('statsSection');
        if (['stats', 'tstats'].includes(command)) {
            statsSection.style.display = 'block';
            statsSection.classList.add('show');
        } else {
            statsSection.style.display = 'none';
            statsSection.classList.remove('show');
        }
    }

    addFilterRow(field = '', operator = '', value = '') {
        const container = document.getElementById('filtersContainer');
        const newRow = document.createElement('div');
        newRow.className = 'filter-row row mb-2';
        newRow.draggable = true;
        newRow.dataset.index = Date.now();
        newRow.innerHTML = `
            <div class="col-md-3">
                <select class="form-select filter-field">
                    <option value="">Select field...</option>
                    <!-- Network & IP Fields -->
                    <option value="clientip">clientip</option>
                    <option value="src_ip">src_ip</option>
                    <option value="dst_ip">dst_ip</option>
                    <option value="src_port">src_port</option>
                    <option value="dst_port">dst_port</option>
                    <option value="protocol">protocol</option>
                    <option value="host">host</option>
                    <option value="source">source</option>
                    <option value="sourcetype">sourcetype</option>
                    <option value="index">index</option>
                    
                    <!-- Web & Application Fields -->
                    <option value="status">status</option>
                    <option value="method">method</option>
                    <option value="uri_path">uri_path</option>
                    <option value="user_agent">user_agent</option>
                    <option value="response_time">response_time</option>
                    <option value="bytes">bytes</option>
                    <option value="referer">referer</option>
                    <option value="url">url</option>
                    <option value="request_uri">request_uri</option>
                    
                    <!-- User & Authentication Fields -->
                    <option value="user">user</option>
                    <option value="username">username</option>
                    <option value="user_id">user_id</option>
                    <option value="session_id">session_id</option>
                    <option value="auth_user">auth_user</option>
                    <option value="login_user">login_user</option>
                    
                    <!-- Security & Event Fields -->
                    <option value="action">action</option>
                    <option value="event_id">event_id</option>
                    <option value="event_type">event_type</option>
                    <option value="severity">severity</option>
                    <option value="priority">priority</option>
                    <option value="category">category</option>
                    <option value="signature">signature</option>
                    <option value="threat_id">threat_id</option>
                    <option value="malware_name">malware_name</option>
                    
                    <!-- Process & System Fields -->
                    <option value="process">process</option>
                    <option value="process_name">process_name</option>
                    <option value="process_id">process_id</option>
                    <option value="parent_process">parent_process</option>
                    <option value="parent_process_id">parent_process_id</option>
                    <option value="command">command</option>
                    <option value="cmdline">cmdline</option>
                    <option value="working_directory">working_directory</option>
                    
                    <!-- File & Access Fields -->
                    <option value="file_path">file_path</option>
                    <option value="file_name">file_name</option>
                    <option value="file_hash">file_hash</option>
                    <option value="file_size">file_size</option>
                    <option value="file_type">file_type</option>
                    <option value="access_type">access_type</option>
                    <option value="permission">permission</option>
                    
                    <!-- Time & Date Fields -->
                    <option value="_time">_time</option>
                    <option value="timestamp">timestamp</option>
                    <option value="date">date</option>
                    <option value="time">time</option>
                    
                    <!-- Custom Field -->
                    <option value="custom">Custom...</option>
                </select>
            </div>
            <div class="col-md-2">
                <select class="form-select filter-operator">
                    <option value="=">=</option>
                    <option value="!=">!=</option>
                    <option value=">">></option>
                    <option value=">=">>=</option>
                    <option value="<"><</option>
                    <option value="<="><=</option>
                    <option value="IN">IN</option>
                    <option value="NOT IN">NOT IN</option>
                    <option value="MATCHES">MATCHES</option>
                    <option value="NOT MATCHES">NOT MATCHES</option>
                </select>
            </div>
            <div class="col-md-5">
                <input type="text" class="form-control filter-value" placeholder="Enter value">
            </div>
            <div class="col-md-2">
                <button type="button" class="btn btn-outline-danger btn-sm remove-filter">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        
        // Set values if provided
        if (field) newRow.querySelector('.filter-field').value = field;
        if (operator) newRow.querySelector('.filter-operator').value = operator;
        if (value) newRow.querySelector('.filter-value').value = value;
        
        container.appendChild(newRow);
    }

    removeFilterRow(button) {
        const row = button.closest('.filter-row');
        row.remove();
    }

    generateSPLCommand() {
        const command = this.buildSPLCommand();
        document.getElementById('generatedCommand').value = command;
        
        // Add to history
        if (command.trim()) {
            this.addToHistory(command);
        }
        
        this.showNotification('SPL command generated successfully!', 'success');
    }

    buildSPLCommand() {
        const searchCommand = document.getElementById('searchCommand').value;
        const index = document.getElementById('indexSelect').value;
        const sourcetype = document.getElementById('sourcetypeSelect').value;
        const timeRange = document.getElementById('timeRange').value;
        const searchString = document.getElementById('searchString').value;
        const outputFormat = document.getElementById('outputFormat').value;
        const limitResults = document.getElementById('limitResults').value;

        let command = '';

        // Handle tstats differently (it doesn't use search string or filters in the same way)
        if (searchCommand === 'tstats') {
            command += 'tstats';
            
            // Add index if specified
            if (index && index !== 'All indexes') {
                command += ` index="${index}"`;
            }

            // Add sourcetype if specified
            if (sourcetype && sourcetype !== 'All source types') {
                command += ` sourcetype="${sourcetype}"`;
            }

            // Add time range
            if (timeRange && timeRange !== 'custom') {
                if (timeRange.includes('earliest=') && timeRange.includes('latest=')) {
                    // Extract earliest and latest values
                    const earliestMatch = timeRange.match(/earliest=([^ ]+)/);
                    const latestMatch = timeRange.match(/latest=([^ ]+)/);
                    if (earliestMatch && latestMatch) {
                        command += ` earliest=${earliestMatch[1]} latest=${latestMatch[1]}`;
                    }
                } else {
                    command += ` | ${timeRange}`;
                }
            }

            // Add stats command
            const statsPart = this.buildStatsCommand();
            if (statsPart) {
                command += ` | ${statsPart}`;
            }
        } else {
            // Standard search command
            command += searchCommand;

            // Add index if specified
            if (index && index !== 'All indexes') {
                command += ` index="${index}"`;
            }

            // Add sourcetype if specified
            if (sourcetype && sourcetype !== 'All source types') {
                command += ` sourcetype="${sourcetype}"`;
            }

            // Add time range
            if (timeRange && timeRange !== 'custom') {
                if (timeRange.includes('earliest=') && timeRange.includes('latest=')) {
                    // Extract earliest and latest values
                    const earliestMatch = timeRange.match(/earliest=([^ ]+)/);
                    const latestMatch = timeRange.match(/latest=([^ ]+)/);
                    if (earliestMatch && latestMatch) {
                        command += ` earliest=${earliestMatch[1]} latest=${latestMatch[1]}`;
                    }
                } else {
                    command += ` | ${timeRange}`;
                }
            }

            // Add search string
            if (searchString.trim()) {
                command += ` ${searchString}`;
            }

            // Add filters
            const filters = this.getFilters();
            if (filters.length > 0) {
                command += ` | where ${filters.join(' AND ')}`;
            }

            // Add stats if applicable
            if (searchCommand === 'stats') {
                const statsPart = this.buildStatsCommand();
                if (statsPart) {
                    command += ` | ${statsPart}`;
                }
            }
        }

        // Add output format
        if (outputFormat && outputFormat !== 'table') {
            command += ` | outputformat ${outputFormat}`;
        }

        // Add limit
        if (limitResults && limitResults > 0) {
            command += ` | head ${limitResults}`;
        }

        return command.trim();
    }

    getFilters() {
        const filters = [];
        const filterRows = document.querySelectorAll('.filter-row');
        
        filterRows.forEach(row => {
            const field = row.querySelector('.filter-field').value;
            const operator = row.querySelector('.filter-operator').value;
            const value = row.querySelector('.filter-value').value;

            if (field && operator && value) {
                let filterValue = value;
                
                // Handle different value types
                if (operator === 'IN' || operator === 'NOT IN') {
                    filterValue = `(${value.split(',').map(v => `"${v.trim()}"`).join(', ')})`;
                } else if (isNaN(value) && operator !== '>' && operator !== '<' && operator !== '>=' && operator !== '<=') {
                    filterValue = `"${value}"`;
                }

                filters.push(`${field} ${operator} ${filterValue}`);
            }
        });

        return filters;
    }

    buildStatsCommand() {
        const function_ = document.getElementById('statsFunction').value;
        const field = document.getElementById('statsField').value;
        const alias = document.getElementById('statsAlias').value;
        const groupBy = document.getElementById('groupByField').value;
        const searchCommand = document.getElementById('searchCommand').value;

        if (!function_) return '';

        let statsCommand = '';
        
        // Build stats command (same for both stats and tstats)
        if (searchCommand === 'tstats') {
            statsCommand = '';
        } else {
            statsCommand = 'stats ';
        }
        
        if (function_ === 'count') {
            statsCommand += 'count';
        } else if (function_ === 'dc') {
            statsCommand += `dc(${field})`;
        } else {
            statsCommand += `${function_}(${field})`;
        }

        if (alias) {
            statsCommand += ` as ${alias}`;
        }

        if (groupBy) {
            statsCommand += ` by ${groupBy}`;
        }

        return statsCommand;
    }

    copyToClipboard() {
        const commandText = document.getElementById('generatedCommand').value;
        if (!commandText) {
            this.showNotification('No command to copy!', 'error');
            return;
        }

        navigator.clipboard.writeText(commandText).then(() => {
            this.showNotification('Command copied to clipboard!', 'success');
        }).catch(() => {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = commandText;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showNotification('Command copied to clipboard!', 'success');
        });
    }

    clearCommand() {
        document.getElementById('generatedCommand').value = '';
        this.showNotification('Command cleared!', 'success');
    }

    showNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'} me-2"></i>
            ${message}
        `;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.classList.add('show');
        }, 100);

        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    // Theme management
    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const icon = document.getElementById('themeIcon');
        icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        
        this.showNotification(`Switched to ${newTheme} theme`, 'success');
    }

    // Configuration management
    saveConfiguration() {
        const config = {
            searchCommand: document.getElementById('searchCommand').value,
            index: document.getElementById('indexSelect').value,
            sourcetype: document.getElementById('sourcetypeSelect').value,
            timeRange: document.getElementById('timeRange').value,
            searchString: document.getElementById('searchString').value,
            filters: this.getCurrentFilters(),
            statsFunction: document.getElementById('statsFunction').value,
            statsField: document.getElementById('statsField').value,
            statsAlias: document.getElementById('statsAlias').value,
            groupByField: document.getElementById('groupByField').value,
            outputFormat: document.getElementById('outputFormat').value,
            limitResults: document.getElementById('limitResults').value,
            timestamp: new Date().toISOString()
        };

        const configName = prompt('Enter configuration name:');
        if (configName) {
            const savedConfigs = JSON.parse(localStorage.getItem('splunkConfigs') || '{}');
            savedConfigs[configName] = config;
            localStorage.setItem('splunkConfigs', JSON.stringify(savedConfigs));
            this.showNotification(`Configuration "${configName}" saved`, 'success');
        }
    }

    loadConfiguration() {
        const savedConfigs = JSON.parse(localStorage.getItem('splunkConfigs') || '{}');
        const configNames = Object.keys(savedConfigs);
        
        if (configNames.length === 0) {
            this.showNotification('No saved configurations found', 'error');
            return;
        }

        const configName = prompt(`Enter configuration name to load:\n\nAvailable: ${configNames.join(', ')}`);
        if (configName && savedConfigs[configName]) {
            const config = savedConfigs[configName];
            this.applyConfiguration(config);
            this.showNotification(`Configuration "${configName}" loaded`, 'success');
        }
    }

    applyConfiguration(config) {
        if (config.searchCommand) document.getElementById('searchCommand').value = config.searchCommand;
        if (config.index) document.getElementById('indexSelect').value = config.index;
        if (config.sourcetype) document.getElementById('sourcetypeSelect').value = config.sourcetype;
        if (config.timeRange) document.getElementById('timeRange').value = config.timeRange;
        if (config.searchString) document.getElementById('searchString').value = config.searchString;
        if (config.statsFunction) document.getElementById('statsFunction').value = config.statsFunction;
        if (config.statsField) document.getElementById('statsField').value = config.statsField;
        if (config.statsAlias) document.getElementById('statsAlias').value = config.statsAlias;
        if (config.groupByField) document.getElementById('groupByField').value = config.groupByField;
        if (config.outputFormat) document.getElementById('outputFormat').value = config.outputFormat;
        if (config.limitResults) document.getElementById('limitResults').value = config.limitResults;
        
        if (config.filters) {
            this.applyFilters(config.filters);
        }
    }

    getCurrentFilters() {
        const filters = [];
        document.querySelectorAll('.filter-row').forEach(row => {
            const field = row.querySelector('.filter-field').value;
            const operator = row.querySelector('.filter-operator').value;
            const value = row.querySelector('.filter-value').value;
            if (field && operator && value) {
                filters.push({ field, operator, value });
            }
        });
        return filters;
    }

    applyFilters(filters) {
        // Clear existing filters
        document.querySelectorAll('.filter-row').forEach(row => row.remove());
        
        // Add new filters
        filters.forEach(filter => {
            this.addFilterRow(filter.field, filter.operator, filter.value);
        });
    }

    // History management
    showHistory() {
        const history = JSON.parse(localStorage.getItem('splunkHistory') || '[]');
        const historyList = document.getElementById('historyList');
        
        if (history.length === 0) {
            historyList.innerHTML = '<div class="text-center text-muted">No command history</div>';
        } else {
            historyList.innerHTML = history.map((item, index) => `
                <div class="list-group-item list-group-item-action" onclick="splGenerator.loadFromHistory(${index})">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <strong>${item.command.substring(0, 50)}...</strong>
                            <br><small class="text-muted">${new Date(item.timestamp).toLocaleString()}</small>
                        </div>
                        <button class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation(); splGenerator.copyFromHistory(${index})">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        }
        
        new bootstrap.Modal(document.getElementById('historyModal')).show();
    }

    loadFromHistory(index) {
        const history = JSON.parse(localStorage.getItem('splunkHistory') || '[]');
        if (history[index]) {
            document.getElementById('generatedCommand').value = history[index].command;
            this.showNotification('Command loaded from history', 'success');
        }
    }

    copyFromHistory(index) {
        const history = JSON.parse(localStorage.getItem('splunkHistory') || '[]');
        if (history[index]) {
            navigator.clipboard.writeText(history[index].command);
            this.showNotification('Command copied from history', 'success');
        }
    }

    clearHistory() {
        localStorage.removeItem('splunkHistory');
        this.showHistory(); // Refresh the modal
        this.showNotification('History cleared', 'success');
    }

    addToHistory(command) {
        const history = JSON.parse(localStorage.getItem('splunkHistory') || '[]');
        history.unshift({
            command: command,
            timestamp: new Date().toISOString()
        });
        
        // Keep only last 50 commands
        if (history.length > 50) {
            history.splice(50);
        }
        
        localStorage.setItem('splunkHistory', JSON.stringify(history));
    }

    // Help system
    showHelp() {
        new bootstrap.Modal(document.getElementById('helpModal')).show();
    }

    // Time range management
    handleTimeRangeChange(value) {
        const customTimeRange = document.getElementById('customTimeRange');
        if (value === 'custom') {
            customTimeRange.style.display = 'block';
        } else {
            customTimeRange.style.display = 'none';
        }
    }

    setQuickTime(timeValue) {
        document.getElementById('customTimeInput').value = timeValue;
    }

    // Auto-save functionality
    setupAutoSave() {
        const inputs = document.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('change', () => {
                this.autoSave();
            });
        });
    }

    autoSave() {
        const config = {
            searchCommand: document.getElementById('searchCommand').value,
            index: document.getElementById('indexSelect').value,
            sourcetype: document.getElementById('sourcetypeSelect').value,
            timeRange: document.getElementById('timeRange').value,
            searchString: document.getElementById('searchString').value,
            filters: this.getCurrentFilters(),
            statsFunction: document.getElementById('statsFunction').value,
            statsField: document.getElementById('statsField').value,
            statsAlias: document.getElementById('statsAlias').value,
            groupByField: document.getElementById('groupByField').value,
            outputFormat: document.getElementById('outputFormat').value,
            limitResults: document.getElementById('limitResults').value
        };

        localStorage.setItem('splunkAutoSave', JSON.stringify(config));
    }

    // Auto-completion
    setupAutoCompletion() {
        const searchString = document.getElementById('searchString');
        const autocompleteData = [
            'host=', 'source=', 'sourcetype=', 'index=', 'status=', 'method=', 'clientip=',
            'user=', 'action=', 'event_id=', 'process=', 'file_path=', 'url=', 'user_agent=',
            'AND', 'OR', 'NOT', 'IN', 'MATCHES', '>', '<', '>=', '<=', '!='
        ];

        searchString.addEventListener('input', (e) => {
            this.showAutoComplete(e.target, autocompleteData);
        });
    }

    showAutoComplete(input, data) {
        const value = input.value;
        const cursorPos = input.selectionStart;
        const wordStart = value.lastIndexOf(' ', cursorPos - 1) + 1;
        const currentWord = value.substring(wordStart, cursorPos);

        if (currentWord.length < 2) {
            this.hideAutoComplete();
            return;
        }

        const matches = data.filter(item => 
            item.toLowerCase().includes(currentWord.toLowerCase())
        );

        if (matches.length === 0) {
            this.hideAutoComplete();
            return;
        }

        this.displayAutoComplete(input, matches, currentWord, wordStart);
    }

    displayAutoComplete(input, matches, currentWord, wordStart) {
        this.hideAutoComplete();

        const dropdown = document.createElement('div');
        dropdown.className = 'autocomplete-dropdown';
        dropdown.style.left = input.offsetLeft + 'px';
        dropdown.style.top = (input.offsetTop + input.offsetHeight) + 'px';
        dropdown.style.width = input.offsetWidth + 'px';

        matches.forEach((match, index) => {
            const item = document.createElement('div');
            item.className = 'autocomplete-item';
            item.textContent = match;
            item.addEventListener('click', () => {
                const value = input.value;
                const newValue = value.substring(0, wordStart) + match + value.substring(input.selectionStart);
                input.value = newValue;
                this.hideAutoComplete();
                input.focus();
            });
            dropdown.appendChild(item);
        });

        document.body.appendChild(dropdown);
    }

    hideAutoComplete() {
        const existing = document.querySelector('.autocomplete-dropdown');
        if (existing) {
            existing.remove();
        }
    }

    // Drag and drop for filters
    setupDragAndDrop() {
        const container = document.getElementById('filtersContainer');
        
        container.addEventListener('dragstart', (e) => {
            if (e.target.classList.contains('filter-row')) {
                e.target.classList.add('dragging');
                e.dataTransfer.setData('text/plain', e.target.dataset.index);
            }
        });

        container.addEventListener('dragend', (e) => {
            if (e.target.classList.contains('filter-row')) {
                e.target.classList.remove('dragging');
            }
        });

        container.addEventListener('dragover', (e) => {
            e.preventDefault();
            const draggingElement = document.querySelector('.dragging');
            if (draggingElement) {
                const afterElement = this.getDragAfterElement(container, e.clientY);
                if (afterElement) {
                    container.insertBefore(draggingElement, afterElement);
                } else {
                    container.appendChild(draggingElement);
                }
            }
        });
    }

    getDragAfterElement(container, y) {
        const draggableElements = [...container.querySelectorAll('.filter-row:not(.dragging)')];
        
        return draggableElements.reduce((closest, child) => {
            const box = child.getBoundingClientRect();
            const offset = y - box.top - box.height / 2;
            
            if (offset < 0 && offset > closest.offset) {
                return { offset: offset, element: child };
            } else {
                return closest;
            }
        }, { offset: Number.NEGATIVE_INFINITY }).element;
    }

    // Real-time validation
    setupRealTimeValidation() {
        const inputs = document.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('input', () => {
                this.validateCurrentCommand();
            });
        });
    }

    validateCurrentCommand() {
        const command = this.buildSPLCommand();
        const isValid = this.validateSPLCommand(command);
        
        if (command.trim()) {
            this.showValidationResult(isValid, command);
        }
    }

    showValidationResult(isValid, command) {
        const toast = document.getElementById('validationToast');
        const message = document.getElementById('validationMessage');
        
        if (isValid) {
            toast.querySelector('.toast-header i').className = 'fas fa-check-circle text-success me-2';
            message.textContent = 'SPL command is valid!';
        } else {
            toast.querySelector('.toast-header i').className = 'fas fa-exclamation-triangle text-warning me-2';
            message.textContent = 'SPL command may have issues. Please review.';
        }
        
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }

    // Initialize theme from localStorage
    initializeTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        const icon = document.getElementById('themeIcon');
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    // Load auto-saved configuration
    loadAutoSave() {
        const savedConfig = localStorage.getItem('splunkAutoSave');
        if (savedConfig) {
            try {
                const config = JSON.parse(savedConfig);
                this.applyConfiguration(config);
            } catch (e) {
                // Auto-save configuration invalid, using defaults
            }
        }
    }

    initializeTemplates() {
        return {
            // DFIR & Security Templates
            'malware-detection': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'WinEventLog:Security OR WinEventLog:System OR Sysmon',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'EventCode=1116 OR EventCode=1117 OR EventCode=1118 OR "malware" OR "virus" OR "trojan" OR "quarantine"',
                filters: [
                    { field: 'EventCode', operator: 'IN', value: '1116,1117,1118,8003,8004' }
                ]
            },
            'suspicious-logins': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'login OR authentication OR "user logon" OR "successful logon" OR "failed logon"',
                filters: [
                    { field: 'status', operator: '=', value: 'success' }
                ]
            },
            'failed-authentication': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'WinEventLog:Security OR access_combined',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'EventCode=4625 OR EventCode=4771 OR status=401 OR status=403',
                filters: [
                    { field: 'EventCode', operator: 'IN', value: '4625,4771' }
                ]
            },
            'privilege-escalation': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'privilege OR elevation OR "run as administrator" OR sudo OR su OR "user rights" OR "security log"',
                filters: [
                    { field: 'action', operator: '=', value: 'elevation' }
                ]
            },
            'data-exfiltration': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'web_access OR network_traffic',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'large download OR "file transfer" OR "data export" OR "bulk download" OR "mass download"',
                filters: [
                    { field: 'bytes', operator: '>', value: '10000000' }
                ]
            },
            'command-execution': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'Sysmon OR WinEventLog:Security',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'EventCode=1 OR "cmd.exe" OR "powershell.exe" OR "process creation"',
                filters: [
                    { field: 'Image', operator: 'MATCHES', value: '.*\\.(exe|bat|ps1)$' }
                ]
            },
            'lateral-movement': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'WinEventLog:Security OR Sysmon',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'EventCode=4624 OR EventCode=4625 OR "psexec" OR "wmic" OR "remote desktop"',
                filters: [
                    { field: 'LogonType', operator: 'IN', value: '3,8,9,10' }
                ]
            },
            'persistence-mechanisms': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'WinEventLog:Security OR WinEventLog:System OR Sysmon',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'EventCode=13 OR EventCode=14 OR EventCode=106 OR EventCode=7045 OR "registry" OR "scheduled task"',
                filters: [
                    { field: 'EventCode', operator: 'IN', value: '13,14,106,7045' }
                ]
            },

            // Network Security Templates
            'port-scanning': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR firewall',
                timeRange: 'earliest=-1h latest=now',
                searchString: 'status=444 OR status=445 OR status=446 OR "port scan" OR "connection attempt"',
                filters: [
                    { field: 'status', operator: '>=', value: '400' }
                ]
            },
            'ddos-attacks': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR firewall',
                timeRange: 'earliest=-1h latest=now',
                searchString: 'status=429 OR status=503 OR "rate limit" OR "connection flood" OR "DDoS"',
                filters: [
                    { field: 'status', operator: 'IN', value: '429,503,444' }
                ]
            },
            'vpn-connections': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'WinEventLog:Security OR access_combined',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'EventCode=4624 OR "VPN" OR "virtual private network" OR "tunnel"',
                filters: [
                    { field: 'LogonType', operator: '=', value: '7' }
                ]
            },
            'firewall-events': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'firewall OR access_combined',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'status=403 OR status=444 OR "firewall" OR "access denied" OR "blocked"',
                filters: [
                    { field: 'status', operator: 'IN', value: '403,444,445' }
                ]
            },
            'proxy-usage': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR web_access',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'X-Forwarded-For OR "via proxy" OR "proxy server" OR "forwarded"',
                filters: [
                    { field: 'http_user_agent', operator: 'MATCHES', value: '.*proxy.*' }
                ]
            },
            'tor-traffic': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR web_access',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'tor OR "onion router" OR "exit node" OR "tor network"',
                filters: [
                    { field: 'http_user_agent', operator: 'MATCHES', value: '.*tor.*' }
                ]
            },

            // Web Security Templates
            'sql-injection': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR web_error',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'status=500 OR "union select" OR "drop table" OR "insert into" OR "or 1=1" OR "or true"',
                filters: [
                    { field: 'status', operator: '>=', value: '400' }
                ]
            },
            'xss-attacks': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR web_error',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'status=400 OR "script" OR "javascript" OR "alert(" OR "onload=" OR "onerror="',
                filters: [
                    { field: 'status', operator: '>=', value: '400' }
                ]
            },
            'file-upload-attacks': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'method=POST OR "upload" OR ".php" OR ".jsp" OR ".asp" OR ".exe" OR ".bat"',
                filters: [
                    { field: 'method', operator: '=', value: 'POST' }
                ]
            },
            'directory-traversal': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR web_error',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'status=404 OR ".." OR "../" OR "..\\" OR "path traversal" OR "../../"',
                filters: [
                    { field: 'status', operator: '>=', value: '400' }
                ]
            },
            'api-abuse': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined OR api_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'status=429 OR "rate limit" OR "throttling" OR "abuse" OR "excessive requests"',
                filters: [
                    { field: 'status', operator: '=', value: '429' }
                ]
            },
            'bot-traffic': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'access_combined',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'bot OR crawler OR spider OR "user agent" OR "automated" OR "scraper"',
                filters: [
                    { field: 'http_user_agent', operator: 'MATCHES', value: '.*bot.*' }
                ]
            },

            // System Monitoring Templates
            'error-logs': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'web_error OR application_logs OR system_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'ERROR OR error OR Error OR "error" OR "ERROR" OR "exception" OR "failure"',
                filters: [
                    { field: 'status', operator: '>=', value: '400' }
                ]
            },
            'performance-metrics': {
                searchCommand: 'tstats',
                index: 'performance',
                sourcetype: '',
                timeRange: 'earliest=-4h latest=now',
                searchString: '',
                statsFunction: 'avg',
                statsField: 'cpu_usage',
                groupBy: 'host',
                outputFormat: 'table',
                limitResults: '15'
            },
            'disk-usage': {
                searchCommand: 'search',
                index: 'system',
                sourcetype: 'system_metrics OR performance',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'disk OR "disk usage" OR "disk space" OR "storage" OR "capacity"',
                filters: [
                    { field: 'usage_percent', operator: '>', value: '80' }
                ]
            },
            'memory-usage': {
                searchCommand: 'search',
                index: 'system',
                sourcetype: 'system_metrics OR performance',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'memory OR "memory usage" OR "RAM" OR "virtual memory"',
                filters: [
                    { field: 'memory_usage', operator: '>', value: '90' }
                ]
            },
            'service-status': {
                searchCommand: 'search',
                index: 'system',
                sourcetype: 'service_logs OR system_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'service OR "service status" OR "service stopped" OR "service failed" OR "service error"',
                filters: [
                    { field: 'status', operator: '=', value: 'stopped' },
                    { field: 'status', operator: '=', value: 'failed' }
                ]
            },
            'process-monitoring': {
                searchCommand: 'search',
                index: 'system',
                sourcetype: 'process_logs OR system_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'process OR "process creation" OR "process termination" OR "new process"',
                filters: [
                    { field: 'action', operator: '=', value: 'create' }
                ]
            },

            // User Activity Templates
            'user-activity': {
                searchCommand: 'stats',
                index: 'main',
                sourcetype: 'access_combined OR web_access',
                timeRange: 'earliest=-7d latest=now',
                searchString: '',
                statsFunction: 'count',
                statsField: '',
                groupBy: 'user',
                outputFormat: 'table',
                limitResults: '50'
            },
            'top-ips': {
                searchCommand: 'stats',
                index: 'main',
                sourcetype: 'access_combined OR web_access',
                timeRange: 'earliest=-24h latest=now',
                searchString: '',
                statsFunction: 'count',
                statsField: '',
                groupBy: 'clientip',
                outputFormat: 'table',
                limitResults: '10'
            },
            'response-times': {
                searchCommand: 'stats',
                index: 'main',
                sourcetype: 'access_combined OR web_access',
                timeRange: 'earliest=-1h latest=now',
                searchString: '',
                statsFunction: 'avg',
                statsField: 'response_time',
                groupBy: 'uri_path',
                outputFormat: 'table',
                limitResults: '20'
            },
            'file-access': {
                searchCommand: 'search',
                index: 'main',
                sourcetype: 'file_access OR audit_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'file OR "file access" OR "file read" OR "file write" OR "file delete"',
                filters: [
                    { field: 'action', operator: '=', value: 'access' }
                ]
            },
            'login-patterns': {
                searchCommand: 'stats',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'login OR authentication OR "user logon"',
                statsFunction: 'count',
                statsField: '',
                groupBy: 'user',
                outputFormat: 'table',
                limitResults: '20'
            },
            'session-duration': {
                searchCommand: 'stats',
                index: 'main',
                sourcetype: 'web_access OR session_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: '',
                statsFunction: 'avg',
                statsField: 'session_duration',
                groupBy: 'user',
                outputFormat: 'table',
                limitResults: '20'
            },

            // Compliance & Audit Templates
            'gdpr-compliance': {
                searchCommand: 'search',
                index: 'audit',
                sourcetype: 'audit_logs OR data_access',
                timeRange: 'earliest=-30d latest=now',
                searchString: 'personal data OR PII OR "personal information" OR "data access" OR "data export"',
                filters: [
                    { field: 'data_type', operator: '=', value: 'personal' }
                ]
            },
            'pci-audit': {
                searchCommand: 'search',
                index: 'audit',
                sourcetype: 'audit_logs OR payment_logs',
                timeRange: 'earliest=-30d latest=now',
                searchString: 'credit card OR payment OR "card number" OR "payment processing" OR PCI',
                filters: [
                    { field: 'compliance', operator: '=', value: 'PCI' }
                ]
            },
            'sox-compliance': {
                searchCommand: 'search',
                index: 'audit',
                sourcetype: 'audit_logs OR financial_logs',
                timeRange: 'earliest=-30d latest=now',
                searchString: 'financial OR accounting OR "financial data" OR "SOX" OR "Sarbanes-Oxley"',
                filters: [
                    { field: 'compliance', operator: '=', value: 'SOX' }
                ]
            },
            'access-reviews': {
                searchCommand: 'search',
                index: 'audit',
                sourcetype: 'audit_logs OR access_logs',
                timeRange: 'earliest=-30d latest=now',
                searchString: 'access OR "access review" OR "permission change" OR "role change" OR "privilege change"',
                filters: [
                    { field: 'action', operator: '=', value: 'change' }
                ]
            },
            'data-classification': {
                searchCommand: 'search',
                index: 'audit',
                sourcetype: 'audit_logs OR data_logs',
                timeRange: 'earliest=-30d latest=now',
                searchString: 'classified OR "sensitive data" OR "confidential" OR "restricted" OR "data classification"',
                filters: [
                    { field: 'classification', operator: 'IN', value: 'confidential,restricted,sensitive' }
                ]
            },
            'audit-trail': {
                searchCommand: 'search',
                index: 'audit',
                sourcetype: 'audit_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'audit OR "audit trail" OR "audit log" OR "audit event"',
                filters: [
                    { field: 'audit_type', operator: '=', value: 'audit' }
                ]
            },

            // Additional DFIR & Security Templates
            'ransomware-activity': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog OR file_access',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'ransomware OR "file encryption" OR "encrypted files" OR ".encrypted" OR ".locked" OR "crypto" OR "bitcoin" OR "payment"',
                filters: [
                    { field: 'action', operator: '=', value: 'encrypt' }
                ]
            },
            'suspicious-processes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog OR process_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'process OR "new process" OR "process creation" OR "suspicious process" OR "unknown process"',
                filters: [
                    { field: 'process_name', operator: 'MATCHES', value: '.*\\.(exe|dll|bat|ps1|vbs|js)$' }
                ]
            },
            'network-connections': {
                searchCommand: 'search',
                index: 'network',
                sourcetype: 'network_traffic OR firewall OR ids',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'connection OR "network connection" OR "outbound connection" OR "inbound connection" OR "established connection"',
                filters: [
                    { field: 'action', operator: '=', value: 'established' }
                ]
            },
            'dns-queries': {
                searchCommand: 'search',
                index: 'network',
                sourcetype: 'dns OR network_traffic',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'dns OR "domain query" OR "name resolution" OR "lookup" OR "resolve"',
                filters: [
                    { field: 'query_type', operator: '=', value: 'A' }
                ]
            },
            'file-system-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'file_access OR audit_logs OR windows_security',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'file OR "file creation" OR "file modification" OR "file deletion" OR "file access"',
                filters: [
                    { field: 'action', operator: 'IN', value: 'create,modify,delete' }
                ]
            },
            'registry-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR registry_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'registry OR "registry key" OR "registry value" OR "registry modification" OR "registry access"',
                filters: [
                    { field: 'action', operator: '=', value: 'modify' }
                ]
            },
            'scheduled-tasks': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR system_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'scheduled OR "scheduled task" OR "task scheduler" OR "cron" OR "at command"',
                filters: [
                    { field: 'action', operator: '=', value: 'create' }
                ]
            },
            'service-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR service_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'service OR "service creation" OR "service modification" OR "service start" OR "service stop"',
                filters: [
                    { field: 'action', operator: 'IN', value: 'create,modify,start,stop' }
                ]
            },
            'user-account-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog OR audit_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'user OR "user creation" OR "user modification" OR "user deletion" OR "account change"',
                filters: [
                    { field: 'action', operator: 'IN', value: 'create,modify,delete' }
                ]
            },
            'group-membership-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog OR audit_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'group OR "group membership" OR "group change" OR "role change" OR "permission change"',
                filters: [
                    { field: 'action', operator: '=', value: 'modify' }
                ]
            },
            'network-shares': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR network_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'share OR "network share" OR "file sharing" OR "shared folder" OR "access to share"',
                filters: [
                    { field: 'action', operator: '=', value: 'access' }
                ]
            },
            'remote-desktop-activity': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR rdp_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'rdp OR "remote desktop" OR "terminal services" OR "remote connection" OR "mstsc"',
                filters: [
                    { field: 'action', operator: '=', value: 'connect' }
                ]
            },
            'powershell-activity': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR powershell_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'powershell OR "powershell.exe" OR "script execution" OR "command execution" OR "ps1"',
                filters: [
                    { field: 'process', operator: '=', value: 'powershell.exe' }
                ]
            },
            'wmi-activity': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR wmi_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'wmi OR "windows management instrumentation" OR "wmic" OR "wbem" OR "cim"',
                filters: [
                    { field: 'action', operator: '=', value: 'execute' }
                ]
            },
            'certificate-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR certificate_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'certificate OR "cert store" OR "certificate store" OR "ssl cert" OR "tls cert"',
                filters: [
                    { field: 'action', operator: 'IN', value: 'install,remove,modify' }
                ]
            },
            'antivirus-events': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'antivirus_logs OR security_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'antivirus OR "virus scan" OR "threat detected" OR "malware detected" OR "quarantine" OR "clean"',
                filters: [
                    { field: 'severity', operator: '>=', value: 'medium' }
                ]
            },
            'firewall-rule-changes': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'firewall_logs OR windows_security',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'firewall OR "firewall rule" OR "rule change" OR "access rule" OR "security rule"',
                filters: [
                    { field: 'action', operator: 'IN', value: 'add,modify,delete' }
                ]
            },
            'email-security': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'email_logs OR mail_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'email OR "phishing" OR "spam" OR "malicious email" OR "suspicious attachment" OR "quarantine"',
                filters: [
                    { field: 'action', operator: '=', value: 'blocked' }
                ]
            },
            'web-proxy-analysis': {
                searchCommand: 'search',
                index: 'network',
                sourcetype: 'web_access OR proxy_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'proxy OR "web access" OR "http request" OR "https request" OR "url access"',
                filters: [
                    { field: 'status', operator: '>=', value: '400' }
                ]
            },
            'network-protocols': {
                searchCommand: 'search',
                index: 'network',
                sourcetype: 'network_traffic OR ids',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'protocol OR "tcp" OR "udp" OR "icmp" OR "http" OR "https" OR "ftp" OR "smtp"',
                filters: [
                    { field: 'protocol', operator: 'IN', value: 'tcp,udp,icmp' }
                ]
            },
            'system-integrity': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'integrity_logs OR system_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'integrity OR "file integrity" OR "system integrity" OR "checksum" OR "hash mismatch"',
                filters: [
                    { field: 'status', operator: '=', value: 'violation' }
                ]
            },
            'backup-monitoring': {
                searchCommand: 'search',
                index: 'system',
                sourcetype: 'backup_logs OR system_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'backup OR "backup job" OR "backup status" OR "backup failure" OR "restore"',
                filters: [
                    { field: 'status', operator: '=', value: 'failed' }
                ]
            },
            'patch-management': {
                searchCommand: 'search',
                index: 'system',
                sourcetype: 'patch_logs OR system_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'patch OR "update" OR "hotfix" OR "security update" OR "vulnerability" OR "cve"',
                filters: [
                    { field: 'status', operator: '=', value: 'installed' }
                ]
            },
            'vulnerability-scan': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'vulnerability_logs OR scan_logs',
                timeRange: 'earliest=-7d latest=now',
                searchString: 'vulnerability OR "security scan" OR "penetration test" OR "security assessment" OR "cve"',
                filters: [
                    { field: 'severity', operator: '>=', value: 'high' }
                ]
            },
            'incident-timeline': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'windows_security OR linux_syslog OR network_traffic OR web_access',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'incident OR "security event" OR "alert" OR "threat" OR "attack" OR "breach"',
                filters: [
                    { field: 'severity', operator: '>=', value: 'medium' }
                ]
            },
            'data-loss-prevention': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'dlp_logs OR data_access OR audit_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'dlp OR "data loss" OR "data leak" OR "sensitive data" OR "policy violation" OR "data exfiltration"',
                filters: [
                    { field: 'action', operator: '=', value: 'blocked' }
                ]
            },
            'endpoint-detection': {
                searchCommand: 'search',
                index: 'security',
                sourcetype: 'edr_logs OR endpoint_logs OR security_logs',
                timeRange: 'earliest=-24h latest=now',
                searchString: 'edr OR "endpoint detection" OR "endpoint response" OR "threat hunting" OR "behavioral analysis"',
                filters: [
                    { field: 'severity', operator: '>=', value: 'medium' }
                ]
            }
        };
    }

    loadTemplate(templateName) {
        const template = this.templates[templateName];
        if (!template) return;

        // Clear existing filters
        const filtersContainer = document.getElementById('filtersContainer');
        filtersContainer.innerHTML = '';

        // Set form values
        document.getElementById('searchCommand').value = template.searchCommand;
        document.getElementById('indexSelect').value = template.index || '';
        document.getElementById('sourcetypeSelect').value = template.sourcetype || '';
        document.getElementById('timeRange').value = template.timeRange || '';
        document.getElementById('searchString').value = template.searchString || '';
        document.getElementById('outputFormat').value = template.outputFormat || 'table';
        document.getElementById('limitResults').value = template.limitResults || '';

        // Handle stats section
        this.handleSearchCommandChange(template.searchCommand);

        if (template.statsFunction) {
            document.getElementById('statsFunction').value = template.statsFunction;
            document.getElementById('statsField').value = template.statsField || '';
            document.getElementById('groupByField').value = template.groupBy || '';
        }

        // Add filters
        if (template.filters) {
            template.filters.forEach(filter => {
                this.addFilterRow();
                const lastRow = document.querySelector('.filter-row:last-child');
                lastRow.querySelector('.filter-field').value = filter.field;
                lastRow.querySelector('.filter-operator').value = filter.operator;
                lastRow.querySelector('.filter-value').value = filter.value;
            });
        }

        // Generate command
        this.generateSPLCommand();
        this.showNotification(`Template "${templateName}" loaded!`, 'success');
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SPLGenerator();
});

// Additional utility functions
function escapeSPLValue(value) {
    if (typeof value === 'string') {
        return value.replace(/"/g, '\\"');
    }
    return value;
}

function validateSPLCommand(command) {
    // Basic validation
    if (!command.trim()) {
        return { valid: false, error: 'Command cannot be empty' };
    }

    if (!command.includes('search') && !command.includes('tstats') && !command.includes('stats')) {
        return { valid: false, error: 'Command must start with search, tstats, or stats' };
    }

    return { valid: true };
}

// Export for potential future use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SPLGenerator, escapeSPLValue, validateSPLCommand };
}
