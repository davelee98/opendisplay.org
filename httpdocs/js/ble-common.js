/**
 * Open Display BLE Common Library
 * 
 * Provides a reusable BLE communication interface for Open Display devices.
 * Supports automatic reconnection, built-in config reading handlers, and
 * forward compatibility through YAML configuration.
 */

// Packet sizes and offsets will be calculated dynamically from YAML

class OpenDisplayBLE {
  constructor(options = {}) {
    // Configuration
    this.serviceUUID = options.serviceUUID || 0x2446;
    this.characteristicUUID = options.characteristicUUID || 0x2446;
    this.deviceNamePrefix = options.deviceNamePrefix || 'OD';
    this.maxReconnectAttempts = options.maxReconnectAttempts || 5;
    this.reconnectDelay = options.reconnectDelay || 2000;
    this.gattRetryDelay = options.gattRetryDelay || 150;
    this.gattMaxRetries = options.gattMaxRetries || 2;
    
    // State
    this.device = null;
    this.gattServer = null;
    this.service = null;
    this.characteristic = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.autoReconnectEnabled = true; // disabled by explicit user disconnect
    this.configYAML = null;
    this.packetSchema = null;  // Parsed packet schema from YAML
    this.packetSizes = {};     // Cached packet sizes
    this.packetFieldOffsets = {};  // Cached field offsets per packet type
    
    // Callbacks
    this.onConnect = options.onConnect || null;
    this.onDisconnect = options.onDisconnect || null;
    this.onError = options.onError || null;
    this.onNotification = options.onNotification || null;
    this.onLog = options.onLog || null;
    this.onStatusChange = options.onStatusChange || null;
    this.onFirmwareVersion = options.onFirmwareVersion || null;
    this.onCommandAck = options.onCommandAck || null;
    this.onCommandError = options.onCommandError || null;
    
    // Built-in handlers
    this.configReadState = {
      active: false,
      totalLength: 0,
      receivedLength: 0,
      chunks: {},
      expectedChunks: 0,
      onComplete: null,
      onProgress: null
    };
    
    this.directWriteState = null;
    
    this.dfuState = {
      active: false,
      packets: [],
      totalPackets: 0,
      packetIndex: 0,
      currentBlockId: 0,
      imgArray: "",
      imgArrayLen: 0,
      onProgress: null,
      onComplete: null,
      onError: null
    };
    
    this.firmwareVersionState = {
      active: false,
      onComplete: null
    };
    
    this.msdReadState = {
      active: false,
      onComplete: null,
      timeoutId: null
    };
    
    this.configWriteState = {
      active: false,
      onComplete: null
    };
    
    // Encryption session state
    this.encryptionSession = {
      authenticated: false,
      masterKey: null,  // Uint8Array(16) - master encryption key
      sessionKey: null, // Uint8Array(16) - derived session key
      sessionId: null, // Uint8Array(8) - session identifier
      nonceCounter: 0, // 64-bit counter for data packets (Number, safe up to 2^53)
      lastSeenCounter: 0, // Last accepted counter value (Number)
      replayWindow: new Array(64).fill(0), // Sliding window for replay protection
      sessionStartTime: 0,
      lastActivity: 0,
      integrityFailures: 0,
      authAttempts: 0,
      lastAuthTime: 0,
      clientNonce: null, // Uint8Array(16)
      serverNonce: null, // Uint8Array(16)
      pendingServerNonce: null, // Uint8Array(16) - from challenge
      serverNonceTime: 0,
      deviceId: null // Uint8Array(4) - device unique ID from firmware
    };
    
    // Load YAML config for forward compatibility
    // Default to static absolute URL
    const defaultPath = 'https://opendisplay.org/firmware/toolbox/config.yaml';
    // Delay loading to ensure js-yaml script has time to load
    // Scripts load asynchronously, so we need to wait for them
    const loadConfig = () => {
      this.loadYAMLConfig(options.configYAMLPath || defaultPath);
    };
    
    if (typeof window !== 'undefined') {
      // In browser - wait for scripts to load
      if (document.readyState === 'loading') {
        // DOM still loading - wait for it, then wait a bit more for scripts
        document.addEventListener('DOMContentLoaded', () => {
          setTimeout(loadConfig, 200);
        });
      } else {
        // DOM already loaded - wait a bit for scripts to load
        setTimeout(loadConfig, 200);
      }
    } else {
      // Not in browser - load immediately
      loadConfig();
    }
  }
  
  /**
   * Parse size token (handles numeric values and "variable")
   */
  parseSizeToken(size) {
    if (typeof size === 'number') return size;
    if (typeof size === 'string') {
      if (size === 'variable') return null;
      const num = parseInt(size, 10);
      if (!isNaN(num)) return num;
      return null;
    }
    return null;
  }
  
  /**
   * Calculate packet size from YAML field definitions
   */
  calculatePacketSize(packetDef) {
    if (!packetDef || !packetDef.fields) return null;
    let totalSize = 0;
    for (const field of packetDef.fields) {
      const size = this.parseSizeToken(field.size);
      if (size === null) {
        // Variable size field - can't calculate total
        return null;
      }
      totalSize += size;
    }
    return totalSize;
  }
  
  /**
   * Calculate field offsets from YAML field definitions
   */
  calculateFieldOffsets(packetDef) {
    if (!packetDef || !packetDef.fields) return {};
    const offsets = {};
    let currentOffset = 0;
    for (const field of packetDef.fields) {
      offsets[field.name] = currentOffset;
      const size = this.parseSizeToken(field.size);
      if (size === null) {
        // Variable size field - stop here
        break;
      }
      currentOffset += size;
    }
    return offsets;
  }
  
  /**
   * Simple YAML parser for packet_types section (basic implementation)
   * This is a minimal parser that extracts packet_types from YAML
   */
  parseYAMLBasic(yamlText) {
    try {
      // Try using jsyaml if available (check multiple possible names and scopes)
      // js-yaml.min.js exposes jsyaml on globalThis/self/window
      let yamlLoader = null;
      let jsyamlObj = null;
      
      // Check global scope (works in most cases)
      if (typeof jsyaml !== 'undefined') {
        jsyamlObj = jsyaml;
      } 
      // Check window scope (fallback)
      else if (typeof window !== 'undefined' && typeof window.jsyaml !== 'undefined') {
        jsyamlObj = window.jsyaml;
      }
      // Check globalThis (modern browsers)
      else if (typeof globalThis !== 'undefined' && typeof globalThis.jsyaml !== 'undefined') {
        jsyamlObj = globalThis.jsyaml;
      }
      // Check self (web workers)
      else if (typeof self !== 'undefined' && typeof self.jsyaml !== 'undefined') {
        jsyamlObj = self.jsyaml;
      }
      // Check alternative name
      else if (typeof jsYAML !== 'undefined') {
        jsyamlObj = jsYAML;
      }
      
      if (jsyamlObj && jsyamlObj.load) {
        yamlLoader = jsyamlObj.load;
      }
      
      if (yamlLoader) {
        try {
          const doc = yamlLoader(yamlText);
          if (doc && doc.ble_proto && doc.ble_proto.packet_types) {
            this.log(`Using jsyaml parser, found ${Object.keys(doc.ble_proto.packet_types).length} packet types`, 'info');
            return doc.ble_proto.packet_types;
          } else {
            this.log('jsyaml loaded but packet_types not found in YAML structure', 'warning');
          }
        } catch (error) {
          this.log(`jsyaml parse error: ${error.message}`, 'error');
          return null;
        }
      }
      
      // jsyaml is required - no fallback
      const debugInfo = {
        'typeof jsyaml': typeof jsyaml,
        'typeof window.jsyaml': typeof window !== 'undefined' ? typeof window.jsyaml : 'N/A',
        'typeof globalThis.jsyaml': typeof globalThis !== 'undefined' ? typeof globalThis.jsyaml : 'N/A',
        'typeof self.jsyaml': typeof self !== 'undefined' ? typeof self.jsyaml : 'N/A'
      };
      this.log(`jsyaml not available. Debug: ${JSON.stringify(debugInfo)}`, 'error');
      return null;
    } catch (error) {
      this.log(`YAML parsing error: ${error.message}`, 'error');
      return null;
    }
  }
  
  /**
   * Load YAML configuration and parse packet schema
   */
  async loadYAMLConfig(path) {
    try {
      // Wait for jsyaml to load if scripts are loading asynchronously
      // js-yaml.min.js exposes jsyaml globally, but scripts load async
      if (typeof jsyaml === 'undefined' && typeof window !== 'undefined') {
        // Check if js-yaml script is in the DOM
        const jsyamlScript = document.querySelector('script[src*="js-yaml"], script[src*="jsyaml"]');
        if (jsyamlScript) {
          // Script is in DOM but might not be loaded yet - wait for it
          this.log('js-yaml script found in DOM, waiting for it to load...', 'info');
          let attempts = 0;
          while (attempts < 50 && typeof jsyaml === 'undefined') {
            // Check all possible scopes
            if (typeof window.jsyaml !== 'undefined' || 
                typeof globalThis !== 'undefined' && typeof globalThis.jsyaml !== 'undefined' ||
                typeof self !== 'undefined' && typeof self.jsyaml !== 'undefined') {
              break;
            }
            await this.delay(100);
            attempts++;
          }
          if (typeof jsyaml !== 'undefined' || 
              (typeof window !== 'undefined' && typeof window.jsyaml !== 'undefined') ||
              (typeof globalThis !== 'undefined' && typeof globalThis.jsyaml !== 'undefined')) {
            this.log('jsyaml loaded after waiting', 'info');
          } else {
            this.log('jsyaml still not available after waiting 5 seconds, will use basic parser', 'warning');
          }
        } else {
          // Script not in DOM - list all script tags for debugging
          if (typeof document !== 'undefined') {
            const allScripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            this.log(`js-yaml script not found in DOM. Available scripts: ${allScripts.join(', ')}`, 'info');
          } else {
            this.log('js-yaml script not found in DOM (document not available), will use basic parser', 'info');
          }
        }
      }
      
      const response = await fetch(path);
      if (response.ok) {
        const text = await response.text();
        this.configYAML = text;
        
        // Parse packet types from YAML
        const packetTypes = this.parseYAMLBasic(text);
        if (packetTypes) {
          this.packetSchema = packetTypes;
          
          // Calculate and cache packet sizes and offsets
          for (const [packetIdStr, packetDef] of Object.entries(packetTypes)) {
            const packetId = parseInt(packetIdStr, 10);
            if (isNaN(packetId)) {
              this.log(`Skipping invalid packet ID: ${packetIdStr}`, 'warning');
              continue;
            }
            const size = this.calculatePacketSize(packetDef);
            if (size !== null) {
              this.packetSizes[packetId] = size;
            }
            this.packetFieldOffsets[packetId] = this.calculateFieldOffsets(packetDef);
          }
          
          this.log(`YAML config loaded: ${Object.keys(packetTypes).length} packet types, ${Object.keys(this.packetSizes).length} with fixed sizes`, 'info');
          this.log(`Loaded packet IDs (hex): ${Object.keys(this.packetSizes).map(k => '0x' + parseInt(k).toString(16)).join(', ')}`, 'info');
        } else {
          this.log('YAML config loaded but packet_types could not be parsed', 'warning');
        }
      } else {
        this.log(`Could not load YAML config: HTTP ${response.status}`, 'warning');
      }
    } catch (error) {
      this.log(`Could not load YAML config: ${error.message}`, 'warning');
    }
  }
  
  /**
   * Logging helper
   */
  log(message, type = 'info') {
    if (this.onLog) {
      this.onLog(message, type);
    } else {
      console.log(`[BLE ${type.toUpperCase()}] ${message}`);
    }
  }
  
  /**
   * Status update helper
   */
  setStatus(message, isConnected = false) {
    this.isConnected = isConnected;
    if (this.onStatusChange) {
      this.onStatusChange(message, isConnected);
    }
  }
  
  /**
   * Request device and connect
   */
  async connect(deviceNamePrefix = null) {
    if (this.isConnected && this.device && this.device.gatt && this.device.gatt.connected) {
      this.log('Already connected', 'info');
      return true;
    }
    
    const prefix = deviceNamePrefix || this.deviceNamePrefix;
    if (!prefix) {
      throw new Error('Device name prefix required');
    }
    
    const deviceOptions = {
      optionalServices: [this.serviceUUID],
      filters: prefix.split(',').map(p => p.trim()).filter(p => p).map(p => ({
        namePrefix: p
      }))
    };
    
    if (deviceOptions.filters.length === 0) {
      throw new Error('No valid device filters');
    }
    
    try {
      this.autoReconnectEnabled = true;
      this.log(`Requesting device with filters: ${JSON.stringify(deviceOptions.filters)}`, 'info');
      this.setStatus('Requesting device...', false);
      
      this.device = await navigator.bluetooth.requestDevice(deviceOptions);
      this.log(`Found: ${this.device.name || 'Unknown device'} (${this.device.id})`, 'success');
      this.setStatus(`Found ${this.device.name || 'device'}`, false);
      
      this.device.addEventListener('gattserverdisconnected', () => this.handleDisconnect());
      
      return await this.connectToGATT();
    } catch (error) {
      if (error.name === 'NotFoundError' || error.name === 'AbortError') {
        this.log('No device selected/found', 'error');
        this.setStatus('No device selected', false);
        throw new Error('Device selection cancelled or not found');
      }
      this.handleError(error);
      throw error;
    }
  }
  
  /**
   * Check if encryption is established on the GATT server
   */
  async checkEncryptionStatus() {
    if (!this.gattServer) {
      return false;
    }
    
    try {
      // Try to read a characteristic property to check if encryption is established
      // If encryption is required but not established, this will fail
      if (this.service && this.characteristic) {
        // Characteristic already obtained, encryption should be established
        return true;
      }
      
      // If we don't have the service yet, we can't check encryption
      // Return true to proceed (encryption will be checked when accessing characteristic)
      return true;
    } catch (error) {
      this.log(`Encryption check failed: ${error.name} - ${error.message}`, 'warning');
      return false;
    }
  }
  
  /**
   * Enable notifications with retry logic
   * Some devices need time for encryption to fully establish before CCCD can be written
   */
  async enableNotificationsWithRetry(maxRetries = 5, delayMs = 200) {
    let lastError = null;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        await this.characteristic.startNotifications();
        if (i > 0) {
          this.log(`Notifications enabled after ${i + 1} attempt(s)`, 'success');
        }
        return;
      } catch (error) {
        lastError = error;
        const isRetryableError = error.name === 'NotSupportedError' ||
                                error.name === 'NetworkError' ||
                                error.name === 'SecurityError' ||
                                error.message.toLowerCase().includes('gatt') ||
                                error.message.toLowerCase().includes('unknown') ||
                                error.message.toLowerCase().includes('not supported');
        
        if (isRetryableError && i < maxRetries - 1) {
          this.log(`Retrying notification enable (attempt ${i + 1}/${maxRetries}): ${error.message}`, 'info');
          await new Promise(resolve => setTimeout(resolve, delayMs));
          continue;
        } else {
          // Not a retryable error or max retries reached
          throw error;
        }
      }
    }
    
    // If we get here, all retries failed
    throw lastError || new Error('Failed to enable notifications after retries');
  }
  
  /**
   * Wait for encryption to be established with retries
   * Attempts to get the characteristic, which will trigger encryption if needed
   */
  async waitForEncryptionAndGetCharacteristic(maxRetries = 5, delayMs = 200) {
    let lastError = null;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        // Try to get characteristic (this will trigger encryption if needed)
        const char = await this.service.getCharacteristic(this.characteristicUUID);
        if (char) {
          if (i > 0) {
            this.log(`Encryption established after ${i + 1} attempt(s)`, 'success');
          } else {
            this.log('Characteristic accessible (encryption ready)', 'info');
          }
          return char;
        }
      } catch (error) {
        lastError = error;
        const isSecurityError = error.name === 'SecurityError' || 
                               error.name === 'NetworkError' ||
                               error.message.toLowerCase().includes('encrypt') || 
                               error.message.toLowerCase().includes('security') ||
                               error.message.toLowerCase().includes('not authorized') ||
                               error.message.toLowerCase().includes('insufficient encryption');
        
        if (isSecurityError && i < maxRetries - 1) {
          this.log(`Waiting for encryption (attempt ${i + 1}/${maxRetries}): ${error.message}`, 'info');
          await new Promise(resolve => setTimeout(resolve, delayMs));
          continue;
        } else {
          // Not a security error or max retries reached
          throw error;
        }
      }
    }
    
    // If we get here, all retries failed
    throw lastError || new Error('Failed to establish encryption after retries');
  }
  
  /**
   * Connect to GATT server
   */
  async connectToGATT() {
    if (!this.device) {
      throw new Error('No device selected');
    }
    
    if (this.device.gatt && this.device.gatt.connected) {
      this.log('Already connected to GATT', 'info');
      return true;
    }
    
    try {
      this.autoReconnectEnabled = true;
      this.log(`Connecting to GATT Server on: ${this.device.name || this.device.id}...`, 'info');
      this.setStatus('Connecting...', false);
      
      this.gattServer = await this.device.gatt.connect();
      this.log('GATT Server connected', 'success');
      
      // Log connection state
      this.log(`GATT Server state: connected=${this.gattServer.connected}`, 'info');
      
      this.service = await this.gattServer.getPrimaryService(this.serviceUUID);
      this.log(`Service 0x${this.serviceUUID.toString(16)} found`, 'success');
      
      // Get characteristic with encryption retry logic
      // This will automatically wait for encryption if the characteristic requires it
      this.log('Accessing characteristic (encryption will be established if needed)...', 'info');
      try {
        this.characteristic = await this.waitForEncryptionAndGetCharacteristic(5, 200);
        this.log(`Characteristic 0x${this.characteristicUUID.toString(16)} found`, 'success');
      } catch (charError) {
        this.log(`Failed to get characteristic: ${charError.name} - ${charError.message}`, 'error');
        this.log(`Error details: code=${charError.code}, stack=${charError.stack}`, 'error');
        throw charError;
      }
      
      // Wait a bit for encryption to fully establish before enabling notifications
      this.log('Waiting for encryption to stabilize...', 'info');
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Try to enable notifications with retries
      try {
        await this.enableNotificationsWithRetry(5, 200);
        this.characteristic.addEventListener('characteristicvaluechanged', (event) => this.handleNotification(event));
        this.log('Notifications started', 'success');
      } catch (notifyError) {
        this.log(`Failed to start notifications: ${notifyError.name} - ${notifyError.message}`, 'error');
        this.log(`Error details: code=${notifyError.code}, stack=${notifyError.stack}`, 'error');
        
        // Log additional diagnostic info
        this.log(`Characteristic properties: ${JSON.stringify(this.characteristic.properties || {})}`, 'error');
        try {
          const descriptors = await this.characteristic.getDescriptors();
          this.log(`Available descriptors: ${descriptors.length}`, 'error');
          for (const desc of descriptors) {
            this.log(`  Descriptor UUID: ${desc.uuid}`, 'error');
          }
        } catch (descError) {
          this.log(`Could not get descriptors: ${descError.message}`, 'error');
        }
        
        throw notifyError;
      }
      
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.setStatus('Connected', true);
      
      if (this.onConnect) {
        this.onConnect();
      }
      
      return true;
    } catch (error) {
      this.handleError(error);
      throw error;
    }
  }
  
  /**
   * Disconnect from device
   */
  async disconnect() {
    // User initiated disconnect; don't attempt auto-reconnect from the ensuing
    // gattserverdisconnected event.
    this.autoReconnectEnabled = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    
    if (this.device && this.device.removeEventListener) {
      this.device.removeEventListener('gattserverdisconnected', this.handleDisconnect);
    }
    
    if (this.device && this.device.gatt && this.device.gatt.connected) {
      try {
        await this.device.gatt.disconnect();
      } catch (error) {
        this.log(`Error during disconnect: ${error.message}`, 'warning');
      }
    }
    
    this.resetState();
    this.setStatus('Disconnected', false);
    
    if (this.onDisconnect) {
      this.onDisconnect();
    }
  }
  
  /**
   * Handle disconnection event
   */
  handleDisconnect() {
    this.log('Device disconnected', 'warning');
    this.resetState();
    this.setStatus('Disconnected', false);
    
    if (this.onDisconnect) {
      this.onDisconnect();
    }
    
    // Attempt reconnection unless explicitly disabled by user disconnect
    if (this.autoReconnectEnabled && this.device && this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * this.reconnectAttempts;
      this.log(`Connection lost. Retrying (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms...`, 'info');
      this.setStatus(`Reconnecting ${this.reconnectAttempts}/${this.maxReconnectAttempts}...`, false);
      
      this.reconnectTimer = setTimeout(() => {
        this.connectToGATT().catch(error => {
          if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            this.log('Reconnection failed after max attempts', 'error');
            this.setStatus('Connection failed', false);
            this.device = null;
          }
        });
      }, delay);
    } else {
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        this.log('Max reconnection attempts reached', 'error');
        this.setStatus('Connection failed', false);
      }
      this.device = null;
    }
  }
  
  /**
   * Reset internal state
   */
  resetState() {
    this.gattServer = null;
    this.service = null;
    this.characteristic = null;
    this.isConnected = false;
    this.configReadState.active = false;
    this.configReadState.chunks = {};
    this.configReadState.receivedLength = 0;
    this.configReadState.totalLength = 0;
  }
  
  /**
   * Send command (Uint8Array)
   */
  async sendCommand(cmd) {
    if (!this.characteristic || !this.isConnected) {
      throw new Error('Not connected');
    }
    
    // Check if command should be encrypted
    let commandToSend = cmd;
    if (this.encryptionSession.authenticated && cmd.length >= 2) {
      const commandId = (cmd[0] << 8) | cmd[1];
      // Don't encrypt authentication and firmware version commands
      if (commandId !== 0x0050 && commandId !== 0x0043) {
        try {
          this.log(`Encrypting command 0x${commandId.toString(16).padStart(4, '0')} (${cmd.length} bytes)`, 'info');
          commandToSend = await this.encryptCommand(cmd);
          this.log(`Encrypted command: ${commandToSend.length} bytes`, 'info');
        } catch (error) {
          this.log(`Encryption failed: ${error.message}`, 'error');
          throw error;
        }
      }
    }
    
    let retries = 0;
    while (retries <= this.gattMaxRetries) {
      try {
        await this.characteristic.writeValueWithoutResponse(commandToSend);
        return;
      } catch (error) {
        if (error.name === 'NetworkError' && error.message.includes('GATT operation') && retries < this.gattMaxRetries) {
          this.log(`GATT busy, retrying send (${retries + 1}/${this.gattMaxRetries})...`, 'info');
          await this.delay(this.gattRetryDelay);
          retries++;
        } else {
          throw error;
        }
      }
    }
  }
  
  /**
   * Set encryption master key (prompts user if not provided)
   */
  async setEncryptionKey(key = null) {
    if (key === null) {
      // Prompt user for key
      const keyInput = prompt('Enter encryption key (32 hex characters, e.g., 00112233445566778899AABBCCDDEEFF):');
      if (!keyInput) {
        throw new Error('Encryption key required');
      }
      // Parse hex string
      const hexStr = keyInput.replace(/[^0-9A-Fa-f]/g, '');
      if (hexStr.length !== 32) {
        throw new Error('Encryption key must be exactly 32 hex characters (16 bytes)');
      }
      key = new Uint8Array(16);
      for (let i = 0; i < 16; i++) {
        key[i] = parseInt(hexStr.substr(i * 2, 2), 16);
      }
    }
    
    // Check if key is all zeros (encryption disabled)
    const isZero = key.every(b => b === 0);
    //if (isZero) {
    //  this.log('Encryption key is all zeros - encryption disabled', 'warning');
    //  this.encryptionSession.masterKey = null;
    //  this.encryptionSession.authenticated = false;
    //  return false;
    //}
    
    this.encryptionSession.masterKey = key;
    this.log('Encryption key set, authentication required', 'info');
    return true;
  }
  
  /**
   * Authenticate with device (server-challenge protocol)
   */
  async authenticate() {
    if (!this.encryptionSession.masterKey) {
      throw new Error('Encryption key not set');
    }
    
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    // Check rate limiting
    const now = Date.now();
    if (this.encryptionSession.lastAuthTime > 0) {
      const timeSinceLastAuth = (now - this.encryptionSession.lastAuthTime) / 1000;
      if (timeSinceLastAuth < 60) {
        if (this.encryptionSession.authAttempts >= 10) {
          throw new Error('Authentication rate limit exceeded (10 attempts per minute)');
        }
      } else {
        this.encryptionSession.authAttempts = 0;
      }
    }
    
    this.encryptionSession.authAttempts++;
    this.encryptionSession.lastAuthTime = now;
    
    try {
      // Step 1: Request authentication
      this.log('Requesting authentication...', 'info');
      const authRequest = new Uint8Array([0x00, 0x50, 0x00]);
      await this.sendCommand(authRequest);
      
      // Wait for challenge response
      let challengeResponse = await this.waitForAuthResponse(5000);
      if (!challengeResponse || challengeResponse.length < 3) {
        throw new Error('Invalid challenge response');
      }
      
      const status = challengeResponse[2];
      if (status === 0x02) {
        // Server says already authenticated, but client needs to establish a new session
        // with new keys. Force a new authentication by clearing server session first.
        this.log('Server has existing session, forcing new authentication...', 'info');
        // The server will clear the old session when we send a new auth request
        // Send another auth request to get a fresh challenge
        const authRequest2 = new Uint8Array([0x00, 0x50, 0x00]);
        await this.sendCommand(authRequest2);
        
        // Wait for new challenge response
        challengeResponse = await this.waitForAuthResponse(5000);
        if (!challengeResponse || challengeResponse.length < 3) {
          throw new Error('Invalid challenge response');
        }
        
        const status2 = challengeResponse[2];
        if (status2 === 0x02) {
          // Still says already authenticated - this shouldn't happen, but handle it
          throw new Error('Server session persists, cannot establish new session');
        }
        if (status2 !== 0x00) {
          throw new Error(`Authentication failed: status 0x${status2.toString(16)}`);
        }
      }
      
      // At this point, challengeResponse should have status 0x00
      if (challengeResponse[2] !== 0x00) {
        throw new Error(`Authentication failed: status 0x${challengeResponse[2].toString(16)}`);
      }
      
      // Challenge response format: status (1) + server_nonce (16) + device_id (4) = 23 bytes
      // Support both old format (19 bytes) and new format (23 bytes) for backward compatibility
      if (challengeResponse.length < 19) {
        throw new Error('Challenge response too short');
      }
      
      // Extract server nonce
      const serverNonce = challengeResponse.slice(3, 19);
      
      // Extract device ID (if present, otherwise use default)
      let deviceId;
      if (challengeResponse.length >= 23) {
        deviceId = challengeResponse.slice(19, 23);
        this.log(`Device ID received: ${Array.from(deviceId).map(b => b.toString(16).padStart(2, '0')).join(' ')}`, 'info');
      } else {
        // Old format - use default device ID for backward compatibility
        deviceId = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
        this.log('Using default device ID (old protocol format)', 'info');
      }
      this.encryptionSession.deviceId = deviceId;
      this.encryptionSession.pendingServerNonce = serverNonce;
      this.encryptionSession.serverNonceTime = now;
      
      this.log('Received authentication challenge', 'info');
      
      // Step 2: Generate client nonce and compute challenge response
      const clientNonce = crypto.getRandomValues(new Uint8Array(16));
      this.encryptionSession.clientNonce = clientNonce;
      
      // Build challenge input: server_nonce || client_nonce || device_id
      const challengeInput = new Uint8Array(36);
      challengeInput.set(serverNonce, 0);
      challengeInput.set(clientNonce, 16);
      challengeInput.set(deviceId, 32);
      
      // Compute AES-CMAC
      const challengeResponseMac = await this.aesCmac(this.encryptionSession.masterKey, challengeInput);
      
      // Send client response: client_nonce (16) || challenge_response (16)
      const clientResponse = new Uint8Array(34); // Header (2) + client_nonce (16) + challenge_response (16) = 34 bytes
      clientResponse[0] = 0x00;
      clientResponse[1] = 0x50;
      clientResponse.set(clientNonce, 2);
      clientResponse.set(challengeResponseMac, 18);
      
      await this.sendCommand(clientResponse);
      
      // Wait for server response
      const serverResponse = await this.waitForAuthResponse(5000);
      if (!serverResponse || serverResponse.length < 3) {
        throw new Error('Invalid server response');
      }
      
      const serverStatus = serverResponse[2];
      if (serverStatus !== 0x00) {
        throw new Error(`Authentication failed: status 0x${serverStatus.toString(16)}`);
      }
      
      if (serverResponse.length < 19) {
        throw new Error('Server response too short');
      }
      
      // Extract server response MAC
      const serverResponseMac = serverResponse.slice(3, 19);
      
      // Derive session key first (needed for server response verification)
      await this.deriveSessionKey(clientNonce, serverNonce);
      
      // Verify server response (optional - for mutual authentication)
      // Server computes: CMAC(session_key, server_nonce || client_nonce || device_id)
      const serverInput = new Uint8Array(36);
      serverInput.set(serverNonce, 0);  // server_nonce (16 bytes)
      serverInput.set(clientNonce, 16); // client_nonce (16 bytes)
      serverInput.set(deviceId, 32);     // device_id (4 bytes)
      const expectedServerMac = await this.aesCmac(this.encryptionSession.sessionKey, serverInput);
      
      // Debug: log MACs for troubleshooting
      this.log(`Server response MAC: ${Array.from(serverResponseMac).map(b => b.toString(16).padStart(2, '0')).join(' ')}`, 'info');
      this.log(`Expected server MAC: ${Array.from(expectedServerMac).map(b => b.toString(16).padStart(2, '0')).join(' ')}`, 'info');
      
      if (!this.constantTimeCompare(serverResponseMac, expectedServerMac)) {
        this.log(`MAC mismatch - server sent ${serverResponseMac.length} bytes, expected ${expectedServerMac.length} bytes`, 'error');
        throw new Error('Server response verification failed');
      }
      
      // Store nonces before deriving session ID
      this.encryptionSession.serverNonce = serverNonce;
      
      // Derive session ID
      await this.deriveSessionId();
      
      // Debug: log session ID
      const sessionIdHex = Array.from(this.encryptionSession.sessionId).map(b => b.toString(16).padStart(2, '0')).join(' ');
      this.log(`Session ID derived: ${sessionIdHex}`, 'info');
      
      // Initialize session
      this.encryptionSession.authenticated = true;
      this.encryptionSession.nonceCounter = 0;
      this.encryptionSession.lastSeenCounter = 0;
      this.encryptionSession.integrityFailures = 0;
      this.encryptionSession.sessionStartTime = now;
      this.encryptionSession.lastActivity = now;
      this.encryptionSession.replayWindow.fill(0);
      
      this.log('Authentication successful', 'success');
      return true;
      
    } catch (error) {
      this.encryptionSession.authenticated = false;
      this.log(`Authentication failed: ${error.message}`, 'error');
      throw error;
    }
  }
  
  /**
   * Wait for authentication response
   */
  waitForAuthResponse(timeout = 5000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.authResponseHandler = null;
        reject(new Error('Authentication response timeout'));
      }, timeout);
      
      this.authResponseHandler = (bytes) => {
        const command = (bytes[0] << 8) | bytes[1];
        if (command === 0x0050) {
          clearTimeout(timer);
          this.authResponseHandler = null;
          resolve(bytes);
        }
      };
    });
  }
  
  /**
   * AES-CMAC computation using Web Crypto API
   * Implements RFC 4493 AES-CMAC algorithm
   * Uses AES-CBC with zero IV as a workaround for AES-ECB (not supported in all browsers)
   */
  async aesCmac(key, message) {
    const blockSize = 16;
    
    // Import key for AES-CBC (ECB not available, use CBC with zero IV)
    const keyData = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    );
    
    // Generate subkeys K1 and K2 using zero IV (acts like ECB)
    const zeroBlock = new Uint8Array(16);
    const zeroIV = new Uint8Array(16);
    const lEncrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: zeroIV },
      keyData,
      zeroBlock
    );
    const l = new Uint8Array(lEncrypted).slice(0, 16); // First block only
    
    // Generate K1
    const k1 = this.generateSubkey(l);
    
    // Generate K2
    const k2 = this.generateSubkey(k1);
    
    // Process message
    const n = Math.ceil(message.length / blockSize);
    let lastBlock;
    let useK2 = false;
    
    if (n === 0) {
      lastBlock = new Uint8Array(16);
      lastBlock[0] = 0x80;
      useK2 = true;
    } else {
      const lastBlockStart = (n - 1) * blockSize;
      const lastBlockLength = message.length - lastBlockStart;
      
      if (lastBlockLength === blockSize) {
        lastBlock = new Uint8Array(message.slice(lastBlockStart));
        useK2 = false;
      } else {
        lastBlock = new Uint8Array(16);
        lastBlock.set(message.slice(lastBlockStart));
        lastBlock[lastBlockLength] = 0x80;
        useK2 = true;
      }
    }
    
    // XOR with appropriate subkey
    const subkey = useK2 ? k2 : k1;
    for (let i = 0; i < 16; i++) {
      lastBlock[i] ^= subkey[i];
    }
    
    // CBC-MAC computation (using CBC with zero IV, which acts like ECB for single blocks)
    let c = new Uint8Array(16);
    for (let i = 0; i < n - 1; i++) {
      const block = message.slice(i * blockSize, (i + 1) * blockSize);
      for (let j = 0; j < 16; j++) {
        c[j] ^= block[j];
      }
      // Encrypt using CBC with zero IV (equivalent to ECB for single block)
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: zeroIV },
        keyData,
        c
      );
      c = new Uint8Array(encrypted).slice(0, 16);
    }
    
    // Final block
    for (let i = 0; i < 16; i++) {
      c[i] ^= lastBlock[i];
    }
    const finalEncrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: zeroIV },
      keyData,
      c
    );
    c = new Uint8Array(finalEncrypted).slice(0, 16);
    
    return c;
  }
  
  /**
   * Generate CMAC subkey from L
   */
  generateSubkey(l) {
    const k = new Uint8Array(16);
    const carry = (l[0] & 0x80) !== 0;
    
    // Left shift
    for (let i = 0; i < 15; i++) {
      k[i] = (l[i] << 1) | ((l[i + 1] >> 7) & 1);
    }
    k[15] = l[15] << 1;
    
    // XOR with Rb if carry
    if (carry) {
      k[15] ^= 0x87;
    }
    
    return k;
  }
  
  /**
   * AES-ECB encryption helper (using CBC with zero IV as workaround)
   */
  async aesEncryptECB(keyData, block) {
    const zeroIV = new Uint8Array(16);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: zeroIV },
      keyData,
      block
    );
    return new Uint8Array(encrypted).slice(0, 16); // Return first block only
  }
  
  /**
   * Constant-time comparison
   */
  constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }
  
  /**
   * Derive session key using AES-KDF (SP 800-108 Counter Mode)
   */
  async deriveSessionKey(clientNonce, serverNonce) {
    // Build context: "OpenDisplay session" || device_id || client_nonce || server_nonce
    const deviceId = this.encryptionSession.deviceId || new Uint8Array([0x00, 0x00, 0x00, 0x01]);
    const label = new TextEncoder().encode('OpenDisplay session');
    const context = new Uint8Array(label.length + 1 + deviceId.length + clientNonce.length + serverNonce.length + 2);
    let offset = 0;
    context.set(label, offset);
    offset += label.length;
    context[offset++] = 0x00; // Separator
    context.set(deviceId, offset);
    offset += deviceId.length;
    context.set(clientNonce, offset);
    offset += clientNonce.length;
    context.set(serverNonce, offset);
    offset += serverNonce.length;
    context[offset++] = 0x00; // Length high byte (128 bits = 0x0080)
    context[offset++] = 0x80; // Length low byte
    
    // Compute intermediate via CMAC
    const intermediate = await this.aesCmac(this.encryptionSession.masterKey, context);
    
    // Build final input: counter (8 bytes, value=1, big-endian) || intermediate (8 bytes)
    const finalInput = new Uint8Array(16);
    finalInput[0] = 0x00; // Counter = 1, big-endian
    finalInput[1] = 0x00;
    finalInput[2] = 0x00;
    finalInput[3] = 0x00;
    finalInput[4] = 0x00;
    finalInput[5] = 0x00;
    finalInput[6] = 0x00;
    finalInput[7] = 0x01;
    finalInput.set(intermediate.slice(0, 8), 8);
    
    // Derive session key via AES-ECB (using CBC with zero IV as workaround)
    const keyData = await crypto.subtle.importKey(
      'raw',
      this.encryptionSession.masterKey,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    );
    
    const encrypted = await this.aesEncryptECB(keyData, finalInput);
    this.encryptionSession.sessionKey = encrypted;
  }
  
  /**
   * Derive session ID from nonces
   */
  async deriveSessionId() {
    const input = new Uint8Array(32);
    input.set(this.encryptionSession.clientNonce, 0);
    input.set(this.encryptionSession.serverNonce, 16);
    
    const cmacOutput = await this.aesCmac(this.encryptionSession.sessionKey, input);
    this.encryptionSession.sessionId = cmacOutput.slice(0, 8); // Truncate to 8 bytes
  }
  
  /**
   * Get current nonce for encryption
   */
  getCurrentNonce() {
    const nonce = new Uint8Array(16);
    nonce.set(this.encryptionSession.sessionId, 0);
    
    // Convert counter to big-endian (64-bit)
    // JavaScript numbers are safe integers up to 2^53, which is plenty for counters
    // Use division/modulo instead of bitwise operations to avoid 32-bit limitations
    let counter = this.encryptionSession.nonceCounter;
    
    // Extract bytes from counter (big-endian) - least significant byte first
    for (let i = 7; i >= 0; i--) {
      nonce[8 + i] = counter % 256;
      counter = Math.floor(counter / 256);
    }
    
    return nonce;
  }
  
  /**
   * AES-CCM encryption (RFC 3610 implementation)
   * Note: Web Crypto API doesn't support CCM, so we implement it manually
   * nonce: 16 bytes (session_id: 8 bytes + counter: 8 bytes), but CCM uses 13 bytes
   */
  async aesCcmEncrypt(key, nonce16, ad, plaintext, tagLen = 12) {
    // RFC 3610 AES-CCM implementation
    // Step 1: Compute CBC-MAC (T) over B0, AD, and PLAINTEXT
    // Step 2: Generate keystream S_0, S_1, S_2, ...
    // Step 3: Tag = T XOR S_0[0:tagLen]
    // Step 4: Ciphertext = plaintext XOR S_1 || S_2 || ...
    const blockSize = 16;
    const nonce = nonce16.slice(3); // Extract 13-byte nonce (last 13 bytes)
    const nonceLen = 13;
    const q = 15 - nonceLen; // q = 2 (length field size)
    
    // Build B0 block (RFC 3610 Section 2.2)
    // Flags = 64*Adata + 8*M' + L', where M'=(tagLen-2)/2, L'=q-1
    const b0 = new Uint8Array(16);
    b0[0] = (ad.length > 0 ? 0x40 : 0x00) | (((tagLen - 2) / 2) << 3) | (q - 1);
    b0.set(nonce, 1);
    for (let i = 0; i < q; i++) {
      b0[16 - q + i] = (plaintext.length >> (8 * (q - 1 - i))) & 0xFF;
    }
    
    const keyData = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
    
    // CBC-MAC: Start with B0
    let mac = await this.aesEncryptECB(keyData, b0);
    
    // CBC-MAC: Process additional data
    if (ad.length > 0) {
      let adLenBytes;
      if (ad.length < 0xFF00) {
        adLenBytes = new Uint8Array(2);
        adLenBytes[0] = (ad.length >> 8) & 0xFF;
        adLenBytes[1] = ad.length & 0xFF;
      } else {
        adLenBytes = new Uint8Array(6);
        adLenBytes[0] = 0xFF;
        adLenBytes[1] = 0xFE;
        adLenBytes[2] = (ad.length >> 24) & 0xFF;
        adLenBytes[3] = (ad.length >> 16) & 0xFF;
        adLenBytes[4] = (ad.length >> 8) & 0xFF;
        adLenBytes[5] = ad.length & 0xFF;
      }
      
      const adInput = new Uint8Array(adLenBytes.length + ad.length);
      adInput.set(adLenBytes, 0);
      adInput.set(ad, adLenBytes.length);
      
      const adPaddedLen = Math.ceil(adInput.length / blockSize) * blockSize;
      const adPadded = new Uint8Array(adPaddedLen);
      adPadded.set(adInput);
      
      for (let i = 0; i < adPaddedLen; i += blockSize) {
        const block = adPadded.slice(i, i + blockSize);
        for (let j = 0; j < blockSize; j++) {
          mac[j] ^= block[j];
        }
        mac = await this.aesEncryptECB(keyData, mac);
      }
    }
    
    // CBC-MAC: Process PLAINTEXT (not ciphertext - per RFC 3610)
    if (plaintext.length > 0) {
      const ptPaddedLen = Math.ceil(plaintext.length / blockSize) * blockSize;
      const ptPadded = new Uint8Array(ptPaddedLen);
      ptPadded.set(plaintext);
      
      for (let i = 0; i < ptPaddedLen; i += blockSize) {
        const block = ptPadded.slice(i, i + blockSize);
        for (let j = 0; j < blockSize; j++) {
          mac[j] ^= block[j];
        }
        mac = await this.aesEncryptECB(keyData, mac);
      }
    }
    
    // CTR mode: Build A_0 counter block (RFC 3610 Section 2.3)
    // Flags = L' = q - 1
    const ctr = new Uint8Array(16);
    ctr[0] = (q - 1) & 0x07;
    ctr.set(nonce, 1);
    // Counter starts at 0
    
    // Generate S_0 = AES(A_0) for tag encryption
    const s0 = await this.aesEncryptECB(keyData, ctr);
    
    // Tag = T XOR S_0[0:tagLen] (RFC 3610 Section 2.6)
    const tag = new Uint8Array(tagLen);
    for (let i = 0; i < tagLen; i++) {
      tag[i] = mac[i] ^ s0[i];
    }
    
    // Encrypt plaintext with S_1, S_2, ... (counter starts at 1)
    const ciphertext = new Uint8Array(plaintext.length);
    for (let i = 0; i < plaintext.length; i += blockSize) {
      // Increment counter
      let carry = 1;
      for (let j = 15; j >= 16 - q && carry > 0; j--) {
        const sum = ctr[j] + carry;
        ctr[j] = sum & 0xFF;
        carry = sum >> 8;
      }
      
      const keystream = await this.aesEncryptECB(keyData, ctr);
      const blockLen = Math.min(blockSize, plaintext.length - i);
      for (let j = 0; j < blockLen; j++) {
        ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
      }
    }
    
    return { ciphertext, tag };
  }
  
  /**
   * AES-CCM decryption (RFC 3610 implementation)
   * nonce: 16 bytes (session_id: 8 bytes + counter: 8 bytes), but CCM uses 13 bytes
   */
  async aesCcmDecrypt(key, nonce16, ad, ciphertext, tag, tagLen = 12) {
    // RFC 3610 AES-CCM decryption
    // Step 1: Generate keystream S_0, S_1, S_2, ...
    // Step 2: Decrypt ciphertext using S_1, S_2, ...
    // Step 3: Compute CBC-MAC (T) over B0, AD, and decrypted PLAINTEXT
    // Step 4: Verify tag = T XOR S_0[0:tagLen]
    const blockSize = 16;
    const nonce = nonce16.slice(3); // Extract 13-byte nonce (last 13 bytes)
    const nonceLen = 13;
    const q = 15 - nonceLen; // q = 2
    
    const keyData = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
    
    // CTR mode: Build A_0 counter block
    const ctr = new Uint8Array(16);
    ctr[0] = (q - 1) & 0x07;
    ctr.set(nonce, 1);
    
    // Generate S_0 for tag verification
    const s0 = await this.aesEncryptECB(keyData, ctr);
    
    // Decrypt ciphertext with S_1, S_2, ... (counter starts at 1)
    const plaintext = new Uint8Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i += blockSize) {
      let carry = 1;
      for (let j = 15; j >= 16 - q && carry > 0; j--) {
        const sum = ctr[j] + carry;
        ctr[j] = sum & 0xFF;
        carry = sum >> 8;
      }
      
      const keystream = await this.aesEncryptECB(keyData, ctr);
      const blockLen = Math.min(blockSize, ciphertext.length - i);
      for (let j = 0; j < blockLen; j++) {
        plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
      }
    }
    
    // Compute CBC-MAC over B0, AD, and decrypted PLAINTEXT (not ciphertext)
    const b0 = new Uint8Array(16);
    b0[0] = (ad.length > 0 ? 0x40 : 0x00) | (((tagLen - 2) / 2) << 3) | (q - 1);
    b0.set(nonce, 1);
    for (let i = 0; i < q; i++) {
      b0[16 - q + i] = (plaintext.length >> (8 * (q - 1 - i))) & 0xFF;
    }
    
    let mac = await this.aesEncryptECB(keyData, b0);
    
    // Process additional data
    if (ad.length > 0) {
      let adLenBytes;
      if (ad.length < 0xFF00) {
        adLenBytes = new Uint8Array(2);
        adLenBytes[0] = (ad.length >> 8) & 0xFF;
        adLenBytes[1] = ad.length & 0xFF;
      } else {
        adLenBytes = new Uint8Array(6);
        adLenBytes[0] = 0xFF;
        adLenBytes[1] = 0xFE;
        adLenBytes[2] = (ad.length >> 24) & 0xFF;
        adLenBytes[3] = (ad.length >> 16) & 0xFF;
        adLenBytes[4] = (ad.length >> 8) & 0xFF;
        adLenBytes[5] = ad.length & 0xFF;
      }
      
      const adInput = new Uint8Array(adLenBytes.length + ad.length);
      adInput.set(adLenBytes, 0);
      adInput.set(ad, adLenBytes.length);
      
      const adPaddedLen = Math.ceil(adInput.length / blockSize) * blockSize;
      const adPadded = new Uint8Array(adPaddedLen);
      adPadded.set(adInput);
      
      for (let i = 0; i < adPaddedLen; i += blockSize) {
        const block = adPadded.slice(i, i + blockSize);
        for (let j = 0; j < blockSize; j++) {
          mac[j] ^= block[j];
        }
        mac = await this.aesEncryptECB(keyData, mac);
      }
    }
    
    // Process decrypted plaintext for MAC
    if (plaintext.length > 0) {
      const ptPaddedLen = Math.ceil(plaintext.length / blockSize) * blockSize;
      const ptPadded = new Uint8Array(ptPaddedLen);
      ptPadded.set(plaintext);
      
      for (let i = 0; i < ptPaddedLen; i += blockSize) {
        const block = ptPadded.slice(i, i + blockSize);
        for (let j = 0; j < blockSize; j++) {
          mac[j] ^= block[j];
        }
        mac = await this.aesEncryptECB(keyData, mac);
      }
    }
    
    // Verify tag: computed = T XOR S_0[0:tagLen]
    const computedTag = new Uint8Array(tagLen);
    for (let i = 0; i < tagLen; i++) {
      computedTag[i] = mac[i] ^ s0[i];
    }
    
    if (!this.constantTimeCompare(computedTag, new Uint8Array(tag))) {
      throw new Error('Tag verification failed');
    }
    
    return plaintext;
  }
  
  /**
   * Encrypt command using AES-CCM
   */
  async encryptCommand(plaintext) {
    if (!this.encryptionSession.authenticated || !this.encryptionSession.sessionKey) {
      throw new Error('Not authenticated');
    }
    
    const nonce = this.getCurrentNonce();
    // Increment counter after getting nonce (nonce uses current value)
    this.encryptionSession.nonceCounter++;
    
    // Extract command header (2 bytes) as additional data
    const ad = plaintext.slice(0, 2);
    const payload = plaintext.slice(2);
    
    // Always include a 1-byte length field as part of the encrypted payload
    // This ensures CCM always has at least 1 byte to encrypt, even for zero-byte commands
    const payloadWithLength = new Uint8Array(1 + payload.length);
    payloadWithLength[0] = payload.length & 0xFF; // Length byte
    payloadWithLength.set(payload, 1); // Actual payload
    
    // Encrypt using AES-CCM
    const { ciphertext, tag } = await this.aesCcmEncrypt(
      this.encryptionSession.sessionKey,
      nonce,
      ad,
      payloadWithLength,
      12 // 12-byte tag
    );
    
    // Build encrypted command: header (2) || nonce (16) || encrypted_data || tag (12)
    const result = new Uint8Array(2 + 16 + ciphertext.length + 12);
    result.set(ad, 0);
    result.set(nonce, 2);
    result.set(ciphertext, 18);
    result.set(tag, 18 + ciphertext.length);
    
    this.encryptionSession.lastActivity = Date.now();
    return result;
  }
  
  /**
   * Decrypt response using AES-CCM
   */
  async decryptResponse(ciphertext) {
    if (!this.encryptionSession.authenticated || !this.encryptionSession.sessionKey) {
      throw new Error('Not authenticated');
    }
    
    if (ciphertext.length < 2 + 16 + 12) {
      throw new Error('Encrypted response too short');
    }
    
    const header = ciphertext.slice(0, 2);
    const nonce = ciphertext.slice(2, 18);
    const encryptedData = ciphertext.slice(18, ciphertext.length - 12);
    const tag = ciphertext.slice(ciphertext.length - 12);
    
    // Debug: log nonce and session info
    const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const sessionIdHex = Array.from(this.encryptionSession.sessionId).map(b => b.toString(16).padStart(2, '0')).join(' ');
    this.log(`Decrypting response: nonce=${nonceHex}, sessionId=${sessionIdHex}`, 'info');
    
    // Verify nonce replay protection
    if (!this.verifyNonceReplay(nonce)) {
      this.log(`Nonce replay check failed: nonce session_id=${nonceHex.substring(0, 23)}, expected=${sessionIdHex}`, 'error');
      this.encryptionSession.integrityFailures++;
      if (this.encryptionSession.integrityFailures >= 3) {
        this.encryptionSession.authenticated = false;
        throw new Error('Too many integrity failures, session cleared');
      }
      throw new Error('Nonce replay check failed');
    }
    
    try {
      // Decrypt using AES-CCM
      const plaintextWithLength = await this.aesCcmDecrypt(
        this.encryptionSession.sessionKey,
        nonce,
        header,
        encryptedData,
        tag,
        12 // 12-byte tag
      );
      
      // Extract payload length (first byte)
      if (plaintextWithLength.length < 1) {
        throw new Error('Decrypted data too short (missing length byte)');
      }
      
      const payloadLength = plaintextWithLength[0];
      if (payloadLength > plaintextWithLength.length - 1) {
        throw new Error(`Invalid payload length: ${payloadLength} > ${plaintextWithLength.length - 1}`);
      }
      
      // Extract actual payload (skip length byte)
      const plaintext = plaintextWithLength.slice(1, 1 + payloadLength);
      
      // Build decrypted response: header || decrypted payload
      const result = new Uint8Array(2 + plaintext.length);
      result.set(header, 0);
      result.set(plaintext, 2);
      
      this.encryptionSession.integrityFailures = 0;
      this.encryptionSession.lastActivity = Date.now();
      return result;
      
    } catch (error) {
      this.encryptionSession.integrityFailures++;
      if (this.encryptionSession.integrityFailures >= 3) {
        this.encryptionSession.authenticated = false;
        throw new Error('Decryption failed, session cleared');
      }
      throw new Error('Decryption failed: ' + error.message);
    }
  }
  
  /**
   * Verify nonce replay protection
   */
  verifyNonceReplay(nonce) {
    // Extract session_id and counter
    const nonceSessionId = nonce.slice(0, 8);
    // Extract counter from bytes (big-endian) - use multiplication instead of bitwise shift
    // to avoid 32-bit integer limitations
    let nonceCounter = 0;
    for (let i = 0; i < 8; i++) {
      nonceCounter = nonceCounter * 256 + nonce[8 + i];
    }
    
    // Verify session_id matches
    if (!this.constantTimeCompare(nonceSessionId, this.encryptionSession.sessionId)) {
      this.log(`Replay check: Session ID mismatch (nonce=${Array.from(nonceSessionId).map(b => b.toString(16).padStart(2, '0')).join(' ')}, expected=${Array.from(this.encryptionSession.sessionId).map(b => b.toString(16).padStart(2, '0')).join(' ')})`, 'error');
      return false;
    }
    
    // Check if counter is within replay window
    const counterDiff = nonceCounter - this.encryptionSession.lastSeenCounter;
    if (counterDiff < -32 || counterDiff > 32) {
      this.log(`Replay check: Counter out of window (counter=${nonceCounter}, lastSeen=${this.encryptionSession.lastSeenCounter}, diff=${counterDiff})`, 'error');
      return false;
    }
    
    // Check if already seen (but allow counter 0 if lastSeenCounter is 0 and this is the first message)
    // The replay window is initialized with zeros, so we need to handle the first message specially
    const isFirstMessage = (this.encryptionSession.lastSeenCounter === 0 && 
                            nonceCounter === 0 &&
                            this.encryptionSession.replayWindow.every(v => v === 0));
    
    if (!isFirstMessage && this.encryptionSession.replayWindow.includes(nonceCounter)) {
      this.log(`Replay check: Counter already seen (counter=${nonceCounter}, lastSeen=${this.encryptionSession.lastSeenCounter}, isFirst=${isFirstMessage})`, 'error');
      return false;
    }
    
    // Update replay window
    if (nonceCounter > this.encryptionSession.lastSeenCounter) {
      this.encryptionSession.lastSeenCounter = nonceCounter;
    }
    
    // Add to replay window
    this.encryptionSession.replayWindow.shift();
    this.encryptionSession.replayWindow.push(nonceCounter);
    
    return true;
  }
  
  /**
   * Send command from hex string
   */
  async sendHexCommand(hexString) {
    if (hexString.length % 2 !== 0 || hexString.length < 2) {
      throw new Error(`Invalid hex command format: ${hexString}`);
    }
    
    // Auto-prepend response type if missing
    if (hexString.length === 2) {
      hexString = '00' + hexString;
    }
    
    if (hexString.length < 4 || hexString.length % 2 !== 0) {
      throw new Error(`Invalid command format: ${hexString}`);
    }
    
    const cmd = this.hexToBytes(hexString);
    const commandIdHex = hexString.substring(0, 4);
    const payloadHex = hexString.substring(4);
    const logPayload = payloadHex.length > 40 ? payloadHex.substring(0, 40) + '...' : payloadHex;
    this.log(`CMD> ${commandIdHex} Payload: ${logPayload} (${payloadHex.length / 2}B)`, 'info');
    
    await this.sendCommand(cmd);
  }
  
  /**
   * Handle notification from device
   */
  async handleNotification(event) {
    const value = event.target.value;
    if (!value || value.byteLength === 0) return;
    
    let bytes = new Uint8Array(value.buffer);
    
    // Check if response is encrypted
    // Minimum encrypted response size: 2 (header) + 16 (nonce) + 1 (length byte) + 0 (min payload) + 12 (tag) = 31 bytes
    // If response is shorter than 30 bytes, it's definitely unencrypted
    const MIN_ENCRYPTED_RESPONSE_SIZE = 30;
    const isPotentiallyEncrypted = bytes.length >= MIN_ENCRYPTED_RESPONSE_SIZE;
    
    if (this.encryptionSession.authenticated && bytes.length >= 2 && isPotentiallyEncrypted) {
      const commandId = (bytes[0] << 8) | bytes[1];
      // Don't decrypt authentication and firmware version responses
      if (commandId !== 0x0050 && commandId !== 0x0043) {
        try {
          bytes = await this.decryptResponse(bytes);
        } catch (error) {
          this.log(`Decryption failed: ${error.message}`, 'error');
          // If decryption fails, the response might be unencrypted (e.g., error response)
          // Continue processing as unencrypted response
          this.log(`Treating response as unencrypted due to decryption failure`, 'info');
        }
      }
    }
    
    // Handle authentication responses
    if (this.authResponseHandler) {
      const commandId = (bytes[0] << 8) | bytes[1];
      if (commandId === 0x0050) {
        this.authResponseHandler(bytes);
        return;
      }
    }
    
    const hexString = this.bytesToHex(bytes.buffer);
    
    // Built-in config read handler
    if (this.configReadState.active && this.handleConfigReadNotification(bytes)) {
      return;
    }
    
    // Built-in config write ACK handler
    if (this.configWriteState.active && this.handleConfigWriteNotification(bytes)) {
      return;
    }
    
    // Built-in firmware version handler
    if (this.firmwareVersionState.active && this.handleFirmwareVersionNotification(bytes)) {
      return;
    }
    
    // MSD read (0x0044) response: 0x00 0x44 + 16 bytes
    if (this.msdReadState.active && this.handleMSDReadNotification(bytes)) {
      return;
    }
    
    // Built-in direct write handler
    if (this.directWriteState && this.directWriteState.active && this.handleDirectWriteNotification(bytes, hexString)) {
      // Direct write notification was handled - log it for debugging
      this.log(`BLE< ${hexString}`, 'info');
      return;
    }
    
    // Built-in DFU handler
    if (this.dfuState.active && this.handleDFUNotification(bytes)) {
      return;
    }
    
    // Built-in generic command handlers
    if (this.handleGenericCommandNotification(bytes)) {
      return;
    }
    
    // Call custom notification handler
    if (this.onNotification) {
      this.onNotification(bytes, hexString, event);
    } else {
      this.log(`BLE< ${hexString}`, 'info');
    }
  }
  
  /**
   * Handle config read notifications (built-in handler)
   */
  handleConfigReadNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Authentication required error (0x00 0x40 0xFE) - check this first before length check
    if (responseType === 0x00 && command === 0x40 && bytes.length >= 3 && bytes[2] === 0xFE) {
      this.log('Config read requires authentication (0xFE)', 'error');
      this.configReadState.active = false;
      if (this.configReadState.onComplete) {
        this.configReadState.onComplete(null, new Error('Authentication required (0xFE)'));
      }
      return true;
    }
    
    // Config read error (0xFF 0x40)
    if (responseType === 0xFF && command === 0x40) {
      this.log('Config read failed on device', 'error');
      this.configReadState.active = false;
      if (this.configReadState.onComplete) {
        this.configReadState.onComplete(null, new Error('Config read failed'));
      }
      return true;
    }
    
    // Need at least 4 bytes for valid config read response
    if (bytes.length < 4) return false;
    
    // Config read response (0x00 0x40)
    if (responseType === 0x00 && command === 0x40) {
      const chunkNumber = bytes[2] | (bytes[3] << 8);
      
      if (chunkNumber === 0) {
        // First chunk contains total length
        if (bytes.length >= 6) {
          this.configReadState.totalLength = bytes[4] | (bytes[5] << 8);
          const firstChunkDataSize = bytes.length - 6;
          const subsequentChunkDataSize = 512 - 4;
          const remainingData = this.configReadState.totalLength - firstChunkDataSize;
          this.configReadState.expectedChunks = 1 + Math.ceil(remainingData / subsequentChunkDataSize);
          this.log(`Config read: ${this.configReadState.totalLength} bytes expected in ${this.configReadState.expectedChunks} chunks`, 'info');
        }
        const dataStart = 6;
        const chunkData = Array.from(bytes.slice(dataStart));
        this.configReadState.chunks[0] = chunkData;
        this.configReadState.receivedLength = chunkData.length;
      } else {
        // Subsequent chunks
        const dataStart = 4;
        const chunkData = Array.from(bytes.slice(dataStart));
        this.configReadState.chunks[chunkNumber] = chunkData;
        this.configReadState.receivedLength += chunkData.length;
      }
      
      this.log(`Received chunk ${chunkNumber} (${bytes.length - (chunkNumber === 0 ? 6 : 4)} bytes)`, 'info');
      this.log(`Progress: ${this.configReadState.receivedLength}/${this.configReadState.totalLength} bytes`, 'info');
      
      // Progress callback
      if (this.configReadState.onProgress) {
        this.configReadState.onProgress(this.configReadState.receivedLength, this.configReadState.totalLength);
      }
      
      // Check if complete
      if (this.configReadState.receivedLength >= this.configReadState.totalLength) {
        this.log('All config chunks received, reconstructing...', 'info');
        this.reconstructConfig();
      }
      
      return true;
    }
    
    return false;
  }
  
  /**
   * Handle config write notifications (built-in handler)
   */
  handleConfigWriteNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Config write ACK (0x00 0xCE)
    if (responseType === 0x00 && command === 0xCE) {
      this.log('Config write successful', 'success');
      this.configWriteState.active = false;
      if (this.configWriteState.onComplete) {
        this.configWriteState.onComplete(null);
      }
      return true;
    }
    
    // Config write error (0x00 0xCF)
    if (responseType === 0x00 && command === 0xCF) {
      this.log('Config write failed', 'error');
      this.configWriteState.active = false;
      if (this.configWriteState.onComplete) {
        this.configWriteState.onComplete(new Error('Config write failed'));
      }
      return true;
    }
    
    return false;
  }
  
  /**
   * Handle firmware version notifications (built-in handler)
   */
  handleFirmwareVersionNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Firmware version response (0x00 0x43)
    if (responseType === 0x00 && command === 0x43) {
      if (bytes.length < 6) {
        this.log('Firmware version response too short', 'error');
        this.firmwareVersionState.active = false;
        if (this.firmwareVersionState.onComplete) {
          this.firmwareVersionState.onComplete(null, new Error('Response too short'));
        }
        return true;
      }
      
      try {
        const major = bytes[2];
        const minor = bytes[3];
        const shaLength = bytes[4];
        let sha = '';
        
        if (shaLength > 0 && bytes.length >= 5 + shaLength) {
          const shaBytes = bytes.slice(5, 5 + shaLength);
          sha = Array.from(shaBytes).map(b => String.fromCharCode(b)).join('');
        }
        
        const versionInfo = {
          major: major,
          minor: minor,
          sha: sha
        };
        
        this.firmwareVersionState.active = false;
        if (this.firmwareVersionState.onComplete) {
          this.firmwareVersionState.onComplete(versionInfo, null);
        }
        if (this.onFirmwareVersion) {
          this.onFirmwareVersion(versionInfo);
        }
        return true;
      } catch (e) {
        this.log(`Error parsing firmware version: ${e.message}`, 'error');
        this.firmwareVersionState.active = false;
        if (this.firmwareVersionState.onComplete) {
          this.firmwareVersionState.onComplete(null, e);
        }
        return true;
      }
    }
    
    return false;
  }
  
  _clearMsdReadTimer() {
    if (this.msdReadState.timeoutId) {
      clearTimeout(this.msdReadState.timeoutId);
      this.msdReadState.timeoutId = null;
    }
  }

  /**
   * MSD read response (0x00 0x44 + 16 bytes manufacturer payload)
   */
  handleMSDReadNotification(bytes) {
    if (bytes.length < 2) return false;
    const responseType = bytes[0];
    const command = bytes[1];
    if (responseType !== 0x00 || command !== 0x44) return false;
    this._clearMsdReadTimer();
    const cb = this.msdReadState.onComplete;
    this.msdReadState.onComplete = null;
    this.msdReadState.active = false;
    if (bytes.length < 18) {
      this.log('MSD read response too short', 'error');
      if (cb) cb(null, new Error('MSD response too short'));
      return true;
    }
    const msd = new Uint8Array(bytes.buffer, bytes.byteOffset + 2, 16);
    if (cb) cb(new Uint8Array(msd), null);
    return true;
  }
  
  /**
   * Read 16-byte MSD payload (same layout as BLE advertising manufacturer data body).
   * @param {function(null|Uint8Array, Error|null)=} onComplete
   * @returns {Promise<Uint8Array>}
   */
  async readMsd(onComplete) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    return new Promise((resolve, reject) => {
      this._clearMsdReadTimer();
      this.msdReadState.active = true;
      this.msdReadState.onComplete = (data, err) => {
        if (onComplete) onComplete(data, err);
        if (err) reject(err);
        else resolve(data);
      };
      this.msdReadState.timeoutId = setTimeout(() => {
        if (!this.msdReadState.active) return;
        this._clearMsdReadTimer();
        this.msdReadState.active = false;
        const cb = this.msdReadState.onComplete;
        this.msdReadState.onComplete = null;
        const e = new Error('MSD read timeout');
        if (cb) cb(null, e);
        reject(e);
      }, 8000);
      this.sendHexCommand('0044').catch((e) => {
        this._clearMsdReadTimer();
        this.msdReadState.active = false;
        const cb = this.msdReadState.onComplete;
        this.msdReadState.onComplete = null;
        if (cb) cb(null, e);
        reject(e);
      });
    });
  }
  
  /**
   * Handle generic command notifications (ACK, errors)
   */
  handleGenericCommandNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Command ACK (0x00 0x63)
    if (responseType === 0x00 && command === 0x63) {
      if (this.onCommandAck) {
        this.onCommandAck();
      }
      return true;
    }
    
    // General command error (0xFF 0xFF)
    if (responseType === 0xFF && command === 0xFF) {
      this.log('General command error (FFFF)', 'error');
      if (this.onCommandError) {
        this.onCommandError('FFFF');
      }
      return true;
    }
    
    return false;
  }
  
  /**
   * Handle config write notifications (built-in handler)
   */
  handleConfigWriteNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Config write ACK (0x00 0xCE)
    if (responseType === 0x00 && command === 0xCE) {
      this.log('Config write successful', 'success');
      this.configWriteState.active = false;
      if (this.configWriteState.onComplete) {
        this.configWriteState.onComplete(null);
      }
      return true;
    }
    
    // Config write error (0x00 0xCF)
    if (responseType === 0x00 && command === 0xCF) {
      this.log('Config write failed', 'error');
      this.configWriteState.active = false;
      if (this.configWriteState.onComplete) {
        this.configWriteState.onComplete(new Error('Config write failed'));
      }
      return true;
    }
    
    return false;
  }
  
  /**
   * Handle firmware version notifications (built-in handler)
   */
  handleFirmwareVersionNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Firmware version response (0x00 0x43)
    if (responseType === 0x00 && command === 0x43) {
      if (bytes.length < 6) {
        this.log('Firmware version response too short', 'error');
        this.firmwareVersionState.active = false;
        if (this.firmwareVersionState.onComplete) {
          this.firmwareVersionState.onComplete(null, new Error('Response too short'));
        }
        return true;
      }
      
      try {
        const major = bytes[2];
        const minor = bytes[3];
        const shaLength = bytes[4];
        let sha = '';
        
        if (shaLength > 0 && bytes.length >= 5 + shaLength) {
          const shaBytes = bytes.slice(5, 5 + shaLength);
          sha = Array.from(shaBytes).map(b => String.fromCharCode(b)).join('');
        }
        
        const versionInfo = {
          major: major,
          minor: minor,
          sha: sha
        };
        
        this.firmwareVersionState.active = false;
        if (this.firmwareVersionState.onComplete) {
          this.firmwareVersionState.onComplete(versionInfo, null);
        }
        if (this.onFirmwareVersion) {
          this.onFirmwareVersion(versionInfo);
        }
        return true;
      } catch (e) {
        this.log(`Error parsing firmware version: ${e.message}`, 'error');
        this.firmwareVersionState.active = false;
        if (this.firmwareVersionState.onComplete) {
          this.firmwareVersionState.onComplete(null, e);
        }
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Handle generic command notifications (ACK, errors)
   */
  handleGenericCommandNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Command ACK (0x00 0x63)
    if (responseType === 0x00 && command === 0x63) {
      if (this.onCommandAck) {
        this.onCommandAck();
      }
      return true;
    }
    
    // General command error (0xFF 0xFF)
    if (responseType === 0xFF && command === 0xFF) {
      this.log('General command error (FFFF)', 'error');
      if (this.onCommandError) {
        this.onCommandError('FFFF');
      }
      return true;
    }
    
    return false;
  }
  
  /**
   * Handle DFU notifications (built-in handler)
   */
  handleDFUNotification(bytes) {
    if (bytes.length < 2) return false;
    
    const responseType = bytes[0];
    const command = bytes[1];
    
    // Block request (0x00 0xC6)
    if (responseType === 0x00 && command === 0xC6) {
      try {
        const hexString = this.bytesToHex(bytes.slice(2)).replace(/\s+/g, '');
        const blockRequest = new BlockRequest(hexString);
        blockRequest.display();
        
        this.dfuState.currentBlockId = blockRequest.blockId;
        if (this.dfuState.onProgress) {
          this.dfuState.onProgress(`Device requests Block ${blockRequest.blockId}`);
        }
        
        // Send ACK
        this.sendHexCommand("0002").then(() => {
          setTimeout(() => {
            this.sendDFUBlockData(blockRequest.blockId);
          }, 50);
        }).catch(error => {
          this.log(`DFU error: ${error.message}`, 'error');
          if (this.dfuState.onError) {
            this.dfuState.onError(error);
          }
        });
        return true;
      } catch (e) {
        this.log(`Error parsing Block Request (00C6): ${e.message}`, 'error');
        if (this.dfuState.onError) {
          this.dfuState.onError(e);
        }
        return true;
      }
    }
    
    // Part error (0x00 0xC4)
    if (responseType === 0x00 && command === 0xC4) {
      this.log(`Part Error Block ${this.dfuState.currentBlockId} Part ${this.dfuState.packetIndex}. Retrying...`, 'warning');
      if (this.dfuState.onProgress) {
        this.dfuState.onProgress(`Part Error Retry ${this.dfuState.packetIndex}...`);
      }
      setTimeout(() => this.sendNextDFUPart(), 100);
      return true;
    }
    
    // Part ACK (0x00 0xC5)
    if (responseType === 0x00 && command === 0xC5) {
      this.dfuState.packetIndex++;
      if (this.dfuState.packetIndex < this.dfuState.totalPackets) {
        this.sendNextDFUPart();
      } else {
        this.log(`Block ${this.dfuState.currentBlockId} ACKed. Waiting for next request...`, 'info');
        if (this.dfuState.onProgress) {
          this.dfuState.onProgress(`Block ${this.dfuState.currentBlockId} Sent.`);
        }
      }
      return true;
    }
    
    // Upload OK (0x00 0xC7)
    if (responseType === 0x00 && command === 0xC7) {
      this.log("Upload OK.", 'success');
      if (this.dfuState.onProgress) {
        this.dfuState.onProgress("Upload Complete.");
      }
      this.sendHexCommand("0003").catch(error => {
        this.log(`Error: ${error.message}`, 'error');
      });
      this.resetDFUState();
      if (this.dfuState.onComplete) {
        this.dfuState.onComplete(true, null);
      }
      return true;
    }
    
    // Data already present (0x00 0xC8)
    if (responseType === 0x00 && command === 0xC8) {
      this.log("Device: Data already present.", 'info');
      if (this.dfuState.onProgress) {
        this.dfuState.onProgress("Data already present.");
      }
      this.sendHexCommand("0003").catch(error => {
        this.log(`Error: ${error.message}`, 'error');
      });
      this.resetDFUState();
      if (this.dfuState.onComplete) {
        this.dfuState.onComplete(true, null);
      }
      return true;
    }
    
    // Firmware update successful (0x00 0xC9)
    if (responseType === 0x00 && command === 0xC9) {
      this.log("Firmware update successful ACK.", 'success');
      if (this.dfuState.onProgress) {
        this.dfuState.onProgress("FW Update OK.");
      }
      this.resetDFUState();
      if (this.dfuState.onComplete) {
        this.dfuState.onComplete(true, null);
      }
      return true;
    }
    
    return false;
  }
  
  /**
   * Reset DFU state
   */
  resetDFUState() {
    this.dfuState.active = false;
    this.dfuState.packets = [];
    this.dfuState.totalPackets = 0;
    this.dfuState.packetIndex = 0;
    this.dfuState.currentBlockId = 0;
    this.dfuState.imgArray = "";
    this.dfuState.imgArrayLen = 0;
  }
  
  /**
   * Send next DFU part
   */
  sendNextDFUPart() {
    if (this.dfuState.packetIndex >= this.dfuState.packets.length) {
      this.log("DFU: No more packets to send", 'error');
      return;
    }
    this.log(`Sending packet: ${this.dfuState.packets[this.dfuState.packetIndex]}`, 'info');
    this.sendCommand(this.hexToBytes("0065" + this.dfuState.packets[this.dfuState.packetIndex])).catch(error => {
      this.log(`Send Error: ${error.message}`, 'error');
      if (this.dfuState.onError) {
        this.dfuState.onError(error);
      }
    });
  }
  
  /**
   * Send DFU block data
   */
  async sendDFUBlockData(blockId, largeHexData = null) {
    const hexData = largeHexData || this.dfuState.imgArray;
    const blockSizeHex = (DFU_BLOCK_DATA_SIZE * 2);
    const totalBlocks = Math.ceil(hexData.length / blockSizeHex);
    
    if (blockId >= totalBlocks) {
      this.log(`Block ID ${blockId} exceeds total blocks (${totalBlocks}).`, 'error');
      if (this.dfuState.onError) {
        this.dfuState.onError(new Error(`Block ID ${blockId} exceeds total blocks`));
      }
      return;
    }
    
    const start = blockId * blockSizeHex;
    const end = start + blockSizeHex;
    const blockHexData = hexData.substring(start, end);
    this.log(`Processing block ${blockId + 1}/${totalBlocks}...`, 'info');
    
    // hexToByteArray creates a special format with length prefix and CRC
    const dataBytes = (() => {
      const byteArray = [];
      byteArray.push((blockHexData.length / 2) & 0xff);
      byteArray.push(((blockHexData.length / 2) >> 8) & 0xff);
      byteArray.push(0x00);
      byteArray.push(0x00);
      let theCrc = 0;
      for (let i = 0; i < blockHexData.length; i += 2) {
        theCrc += parseInt(blockHexData.substring(i, i + 2), 16);
        byteArray.push(parseInt(blockHexData.substring(i, i + 2), 16));
      }
      byteArray[2] = theCrc & 0xff;
      byteArray[3] = (theCrc >> 8) & 0xff;
      return byteArray;
    })();
    
    this.dfuState.packets = [];
    this.dfuState.totalPackets = Math.ceil(dataBytes.length / DFU_BLOCK_PART_DATA_SIZE);
    for (let i = 0; i < this.dfuState.totalPackets; i++) {
      const startIdx = i * DFU_BLOCK_PART_DATA_SIZE;
      const slice = dataBytes.slice(startIdx, startIdx + DFU_BLOCK_PART_DATA_SIZE);
      const packet = new BlockPart(blockId, i, slice);
      this.dfuState.packets.push(packet.toHexString());
    }
    this.dfuState.packetIndex = 0;
    this.sendNextDFUPart();
  }
  
  /**
   * Start DFU upload
   * @param {string} hexData - Hex string of firmware data
   * @param {Object} options - Options with onProgress, onComplete, onError callbacks
   */
  async startDFUUpload(hexData, options = {}) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    if (this.dfuState.active) {
      throw new Error('DFU upload already in progress');
    }
    
    this.dfuState.active = true;
    this.dfuState.imgArray = hexData;
    this.dfuState.imgArrayLen = hexData.length;
    this.dfuState.onProgress = options.onProgress || null;
    this.dfuState.onComplete = options.onComplete || null;
    this.dfuState.onError = options.onError || null;
    
    // DFU upload starts when device sends block request (0x00C6)
    // The handler will automatically process it
  }
  
  /**
   * Reconstruct config from chunks
   */
  reconstructConfig() {
    const configBytes = [];
    // Get all chunk numbers and sort them
    const chunkNumbers = Object.keys(this.configReadState.chunks).map(Number).sort((a, b) => a - b);
    
    for (const chunkNum of chunkNumbers) {
      if (this.configReadState.chunks[chunkNum]) {
        configBytes.push(...this.configReadState.chunks[chunkNum]);
      }
    }
    
    this.log(`Reconstructed config: ${configBytes.length} bytes (expected: ${this.configReadState.totalLength}) from ${chunkNumbers.length} chunks`, 'info');
    
    if (configBytes.length !== this.configReadState.totalLength) {
      this.log(`WARNING: Length mismatch! Expected ${this.configReadState.totalLength}, got ${configBytes.length}`, 'warning');
    }
    
    // Call callback BEFORE resetting state
    if (this.configReadState.onComplete) {
      this.log(`Calling config read callback with ${configBytes.length} bytes`, 'info');
      try {
        this.configReadState.onComplete(configBytes, null);
      } catch (error) {
        this.log(`Error in config read callback: ${error.message}`, 'error');
      }
    } else {
      this.log('WARNING: Config read completed but no callback was set', 'warning');
    }
    
    // Reset state AFTER callback
    this.configReadState.active = false;
    this.configReadState.chunks = {};
    this.configReadState.receivedLength = 0;
    this.configReadState.totalLength = 0;
  }
  
  /**
   * Read config from device (built-in handler)
   */
  async readConfig(onComplete, onProgress = null) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    this.configReadState = {
      active: true,
      totalLength: 0,
      receivedLength: 0,
      chunks: {},
      expectedChunks: 0,
      onComplete: onComplete,
      onProgress: onProgress
    };
    
    this.log('Reading current config from device...', 'info');
    await this.sendHexCommand('0040');
  }
  
  /**
   * Error handler
   */
  handleError(error) {
    // Enhanced error logging with all available details
    const errorDetails = {
      name: error.name || 'Unknown',
      message: error.message || 'No error message',
      code: error.code !== undefined ? error.code : 'N/A',
      stack: error.stack || 'No stack trace'
    };
    
    this.log(`Error: ${errorDetails.name} - ${errorDetails.message}`, 'error');
    this.log(`Error code: ${errorDetails.code}`, 'error');
    
    // Log additional context
    if (this.device) {
      this.log(`Device: ${this.device.name || this.device.id}`, 'error');
      this.log(`GATT connected: ${this.device.gatt?.connected || false}`, 'error');
    }
    if (this.gattServer) {
      this.log(`GATT Server connected: ${this.gattServer.connected || false}`, 'error');
    }
    if (this.service) {
      this.log(`Service available: true`, 'error');
    }
    if (this.characteristic) {
      this.log(`Characteristic available: true`, 'error');
    }
    
    // Log full error details for debugging
    this.log(`Full error details: ${JSON.stringify(errorDetails, null, 2)}`, 'error');
    
    this.setStatus(`Error: ${errorDetails.message}`, false);
    
    if (this.onError) {
      this.onError(error);
    }
  }
  
  /**
   * Utility: Convert hex string to Uint8Array
   */
  hexToBytes(hexString) {
    if (typeof hexString !== 'string') hexString = '';
    const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, '');
    if (cleanHex.length % 2 !== 0) {
      this.log('Odd hex string length, padding with 0', 'warning');
      return new Uint8Array(0);
    }
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
    }
    return bytes;
  }
  
  /**
   * Utility: Convert ArrayBuffer/Uint8Array to hex string (space-separated)
   */
  bytesToHex(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  }
  
  /**
   * Convert hex string to Uint8Array (continuous hex, no spaces)
   */
  hexToUint8Array(hex) {
    if (typeof hex !== 'string') {
      return new Uint8Array(0);
    }
    const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
    if (cleanHex.length % 2 !== 0) {
      this.log('Odd hex string length', 'warning');
      return new Uint8Array(0);
    }
    const byteLength = Math.floor(cleanHex.length / 2);
    const bytes = new Uint8Array(byteLength);
    for (let i = 0; i < byteLength; i++) {
      const byteHex = cleanHex.substr(i * 2, 2);
      bytes[i] = parseInt(byteHex, 16);
      if (isNaN(bytes[i])) {
        this.log(`Invalid hex byte "${byteHex}" at position ${i * 2}`, 'warning');
        bytes[i] = 0;
      }
    }
    return bytes;
  }
  
  /**
   * Parse Uint8 from hex string (little-endian, 2 hex chars)
   */
  fromHexUint8(hex) {
    return parseInt(hex.substring(0, 2), 16);
  }
  
  /**
   * Parse Uint16 from hex string (little-endian, 4 hex chars)
   */
  fromHexUint16LE(hex) {
    return parseInt(hex.substring(2, 4) + hex.substring(0, 2), 16);
  }
  
  /**
   * Parse Uint32 from hex string (little-endian, 8 hex chars)
   */
  fromHexUint32LE(hex) {
    return parseInt(hex.substring(6, 8) + hex.substring(4, 6) + hex.substring(2, 4) + hex.substring(0, 2), 16) >>> 0;
  }
  
  /**
   * Get packet size for a given packet ID (from YAML)
   */
  getPacketSize(packetId) {
    // If YAML hasn't loaded yet, log warning
    if (Object.keys(this.packetSizes).length === 0) {
      if (this.configYAML === null) {
        this.log(`Packet size lookup for 0x${packetId.toString(16)}: YAML not loaded yet, packet sizes unavailable`, 'warning');
      } else {
        this.log(`Packet size lookup for 0x${packetId.toString(16)}: YAML loaded but no packet sizes calculated (parsing may have failed)`, 'warning');
      }
      return null;
    }
    
    const size = this.packetSizes[packetId];
    if (size === undefined) {
      this.log(`Packet size lookup for 0x${packetId.toString(16)} (${packetId}): Unknown packet type. Available: ${Object.keys(this.packetSizes).map(k => '0x' + parseInt(k).toString(16) + '(' + k + ')').join(', ') || 'none'}`, 'warning');
    }
    return size || null;
  }
  
  /**
   * Get field offset for a packet type and field name (from YAML)
   */
  getFieldOffset(packetId, fieldName) {
    const offsets = this.packetFieldOffsets[packetId];
    if (!offsets) return null;
    return offsets[fieldName] !== undefined ? offsets[fieldName] : null;
  }
  
  /**
   * Parse display packet fields from raw bytes (using YAML-defined offsets)
   * @param {Uint8Array} packetData - The display packet payload (starting after packet number and ID)
   * @returns {Object|null} Parsed display config or null if invalid
   */
  parseDisplayPacketFields(packetData) {
    if (!packetData || packetData.length < 22) {
      return null;
    }
    
    const packetId = 0x20; // Display packet ID
    const offsets = this.packetFieldOffsets[packetId];
    if (!offsets) {
      this.log('Display packet offsets not available from YAML', 'warning');
      return null;
    }
    
    const getOffset = (fieldName) => offsets[fieldName];
    const readUint16 = (offset) => packetData[offset] | (packetData[offset + 1] << 8);
    
    const result = {
      instanceNumber: packetData[getOffset('instance_number')],
      displayTechnology: packetData[getOffset('display_technology')],
      panelIcType: readUint16(getOffset('panel_ic_type')),
      pixelWidth: readUint16(getOffset('pixel_width')),
      pixelHeight: readUint16(getOffset('pixel_height')),
      activeWidthMm: readUint16(getOffset('active_width_mm')),
      activeHeightMm: readUint16(getOffset('active_height_mm')),
      tagType: readUint16(getOffset('legacy_tagtype')),
      rotation: packetData[getOffset('rotation')],
      resetPin: packetData[getOffset('reset_pin')],
      busyPin: packetData[getOffset('busy_pin')],
      dcPin: packetData[getOffset('dc_pin')],
      csPin: packetData[getOffset('cs_pin')],
      dataPin: packetData[getOffset('data_pin')],
      partialUpdateSupport: packetData[getOffset('partial_update_support')],
      colorScheme: packetData[getOffset('color_scheme')],
      transmissionModes: packetData[getOffset('transmission_modes')],
      clkPin: packetData[getOffset('clk_pin')]
    };
    
    // full_update_mC is optional (may not be in all packets)
    const fullUpdateMcOffset = getOffset('full_update_mC');
    if (fullUpdateMcOffset !== null && packetData.length >= fullUpdateMcOffset + 2) {
      result.fullUpdateMc = readUint16(fullUpdateMcOffset);
    } else {
      result.fullUpdateMc = null;
    }
    
    return result;
  }
  
  /**
   * Parse power option packet fields from raw bytes (using YAML-defined offsets)
   * @param {Uint8Array} packetData - The power option packet payload (starting after packet number and ID)
   * @returns {Object|null} Parsed power option config or null if invalid
   */
  parsePowerOptionPacketFields(packetData) {
    if (!packetData || packetData.length < 18) {
      return null;
    }
    
    const packetId = 0x04; // Power option packet ID
    const offsets = this.packetFieldOffsets[packetId];
    if (!offsets) {
      this.log('Power option packet offsets not available from YAML', 'warning');
      return null;
    }
    
    const getOffset = (fieldName) => offsets[fieldName];
    const readUint24 = (offset) => packetData[offset] | (packetData[offset + 1] << 8) | (packetData[offset + 2] << 16);
    const readUint32 = (offset) => packetData[offset] | (packetData[offset + 1] << 8) | (packetData[offset + 2] << 16) | (packetData[offset + 3] << 24);
    
    const batteryCapacityOffset = getOffset('battery_capacity_mah');
    const deepSleepCurrentOffset = getOffset('deep_sleep_current_ua');
    const capacityEstimatorOffset = getOffset('capacity_estimator');
    
    const result = {
      powerMode: packetData[getOffset('power_mode')],
      batteryCapacity: batteryCapacityOffset !== null ? readUint24(batteryCapacityOffset) : null,
      capacityEstimator: capacityEstimatorOffset !== null ? packetData[capacityEstimatorOffset] : null,
      deepSleepCurrent: deepSleepCurrentOffset !== null && packetData.length >= deepSleepCurrentOffset + 4 ? 
                       readUint32(deepSleepCurrentOffset) : null
    };
    
    return result;
  }
  
  /**
   * Utility: Delay promise
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * Calculate CRC16-CCITT checksum
   */
  crc16ccitt(buf) {
    let crc = 0xFFFF;
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    for (let b of bytes) {
      crc ^= (b << 8);
      for (let i = 0; i < 8; i++) {
        if (crc & 0x8000) {
          crc = ((crc << 1) ^ 0x1021) & 0xFFFF;
        } else {
          crc = (crc << 1) & 0xFFFF;
        }
      }
    }
    return crc & 0xFFFF;
  }
  
  /**
   * Convert number to little-endian byte array
   */
  numToBytesLE(num, size) {
    const out = [];
    for (let i = 0; i < size; i++) {
      out.push(num & 0xFF);
      num = num >> 8;
    }
    return out;
  }
  
  /**
   * Write config to device (non-chunked, for small configs)
   */
  async writeConfig(configBytes, onComplete) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    // Set up config write state for ACK handling
    this.configWriteState.active = true;
    this.configWriteState.onComplete = onComplete || null;
    
    if (configBytes.length > 200) {
      // Use chunked write for large configs
      return await this.writeConfigChunked(configBytes);
    }
    
    // Small config - send in one command (0x0041)
    const hexPayload = this.bytesToHex(configBytes).replace(/\s+/g, '');
    await this.sendHexCommand('0041' + hexPayload);
  }
  
  /**
   * Read firmware version from device
   */
  async readFirmwareVersion(onComplete) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    this.firmwareVersionState.active = true;
    this.firmwareVersionState.onComplete = onComplete || null;
    
    await this.sendHexCommand('0043');
  }
  
  /**
   * Read firmware version from device
   */
  async readFirmwareVersion(onComplete) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    this.firmwareVersionState.active = true;
    this.firmwareVersionState.onComplete = onComplete || null;
    
    await this.sendHexCommand('0043');
  }
  
  /**
   * Write config to device (chunked, for large configs)
   */
  async writeConfigChunked(configBytes) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    const chunkSize = 200;
    const totalChunks = Math.ceil(configBytes.length / chunkSize);
    
    this.log(`Sending ${configBytes.length} bytes in ${totalChunks} chunks (${chunkSize} bytes each)...`, 'info');
    
    // First chunk with total size (command 0x0041)
    const firstChunk = configBytes.slice(0, chunkSize);
    const totalSizeBytes = new Uint8Array(2);
    totalSizeBytes[0] = configBytes.length & 0xFF;
    totalSizeBytes[1] = (configBytes.length >> 8) & 0xFF;
    const firstChunkWithSize = new Uint8Array(2 + firstChunk.length);
    firstChunkWithSize.set(totalSizeBytes, 0);
    firstChunkWithSize.set(firstChunk, 2);
    const hexPayload = this.bytesToHex(firstChunkWithSize).replace(/\s+/g, '');
    await this.sendHexCommand('0041' + hexPayload);
    
    // Subsequent chunks (command 0x0042)
    for (let i = 1; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, configBytes.length);
      const chunk = configBytes.slice(start, end);
      const chunkHex = this.bytesToHex(chunk).replace(/\s+/g, '');
      // Delay between chunks to avoid overwhelming the device
      await this.delay(i * 150);
      await this.sendHexCommand('0042' + chunkHex);
    }
  }
  
  /**
   * Parse config bytes into structured format
   * Returns: { length, version, crcGiven, crcCheck, packets: [...] }
   * Note: This is a simplified parser that extracts packet structure without schema dependency
   */
  parseConfigBytes(configBytes) {
    const view = configBytes instanceof Uint8Array ? configBytes : new Uint8Array(configBytes);
    
    if (view.length < 3) {
      throw new Error('Config data too short');
    }
    
    const len = view[0] | (view[1] << 8);
    const version = view[2];
    
    if (len !== view.length) {
      this.log(`Length mismatch: claimed ${len}, actual ${view.length}`, 'warning');
    }
    
    const crcGiven = view[view.length - 2] | (view[view.length - 1] << 8);
    const body = view.slice(0, view.length - 2);
    const crcCheck = this.crc16ccitt(body);
    
    const result = {
      length: len,
      version: version,
      crcGiven: crcCheck === crcGiven,
      crcValue: crcGiven,
      crcCalculated: crcCheck,
      packets: []
    };
    
    // Parse packets using YAML-defined sizes
    let offset = 3;
    const dataEnd = view.length - 2; // Exclude CRC
    
    while (offset < dataEnd) {
      // Need at least 2 bytes for packet number and ID
      if (offset + 2 > dataEnd) {
        this.log(`Not enough bytes for packet header at offset ${offset} (need 2, have ${dataEnd - offset})`, 'warning');
        break;
      }
      
      const packetNumber = view[offset];
      const packetId = view[offset + 1];
      
      // Get packet payload size from YAML schema (does not include header)
      const payloadSize = this.getPacketSize(packetId);
      
      if (payloadSize === null) {
        // Unknown packet type - skip it and stop parsing
        this.log(`Unknown packet type 0x${packetId.toString(16).padStart(2, '0')}, skipping`, 'warning');
        this.log(`Packet size lookup for 0x${packetId.toString(16)} (${packetId}): Unknown packet type. Available: ${Object.keys(this.packetSizes).map(k => `0x${parseInt(k).toString(16)}(${k})`).join(', ')}`, 'warning');
        break;
      }
      
      // Total packet size = header (2 bytes) + payload size
      const totalPacketSize = 2 + payloadSize;
      
      // Check if we have enough bytes for the complete packet (header + payload)
      if (offset + totalPacketSize > dataEnd) {
        this.log(`Packet 0x${packetId.toString(16)} at offset ${offset}: need ${totalPacketSize} bytes (2 header + ${payloadSize} payload), have ${dataEnd - offset} remaining`, 'warning');
        break;
      }
      
      // Move past packet header (number + ID) to read payload
      offset += 2;
      
      const packetData = view.slice(offset, offset + payloadSize);
      
      const packetInfo = {
        number: packetNumber,
        id: packetId,
        idHex: '0x' + packetId.toString(16).padStart(2, '0').toUpperCase(),
        data: Array.from(packetData),
        dataLength: packetData.length
      };
      
      // Extract structured data for known packet types
      if (packetId === 0x20) {
        // Display packet (0x20) - extract all fields
        const displayFields = this.parseDisplayPacketFields(packetData);
        if (displayFields) {
          packetInfo.displayConfig = displayFields;
        } else {
          this.log(`Display packet (0x20) parsing failed: ${packetData.length} bytes`, 'warning');
        }
      } else if (packetId === 0x04) {
        // Power option packet (0x04) - extract key fields
        const powerFields = this.parsePowerOptionPacketFields(packetData);
        if (powerFields) {
          packetInfo.powerOption = powerFields;
        }
      }
      
      result.packets.push(packetInfo);
      
      // Move past the payload (header was already skipped above with offset += 2)
      offset += payloadSize;
    }
    
    return result;
  }
  
  /**
   * Extract display configuration from parsed config
   * Returns the first display config found (instance 0) or null
   */
  extractDisplayConfig(parsedConfig) {
    if (!parsedConfig || !parsedConfig.packets) {
      return null;
    }
    
    // Find the first display packet (0x20), prefer instance 0
    let displayPacket = null;
    for (const packet of parsedConfig.packets) {
      if (packet.id === 0x20 && packet.displayConfig) {
        if (packet.displayConfig.instanceNumber === 0) {
          return packet.displayConfig;
        }
        if (!displayPacket) {
          displayPacket = packet.displayConfig;
        }
      }
    }
    
    return displayPacket;
  }
  
  /**
   * Reboot device
   */
  async reboot() {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    await this.sendHexCommand('000F');
  }

  /**
   * Request Silicon Labs OTA Apploader / bootloader (CMD 0x0051). Disables auto-reconnect
   * so the browser does not hammer the app GATT while the radio stack is in DFU mode.
   */
  async rebootToBootloader() {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    this.autoReconnectEnabled = false;
    await this.sendHexCommand('0051');
  }

  /**
   * Detect color from RGB values based on color scheme
   * @param {number} r - Red component (0-255)
   * @param {number} g - Green component (0-255)
   * @param {number} b - Blue component (0-255)
   * @param {number} colorScheme - Color scheme (0-6)
   * @returns {string} Color name ('black', 'white', 'red', 'yellow', 'green', 'blue')
   */
  detectColor(r, g, b, colorScheme) {
    if (colorScheme === 6) {
      const y = 0.299 * r + 0.587 * g + 0.114 * b;
      const lev = Math.min(15, Math.max(0, Math.round((y * 15) / 255)));
      if (lev <= 2) return 'black';
      if (lev >= 13) return 'white';
      return 'gray_mid';
    }
    if (colorScheme === 5) {
      const gray = (r + g + b) / 3;
      if (gray < 64) return 'black';
      if (gray < 128) return 'gray1';
      if (gray < 192) return 'gray2';
      return 'white';
    }
    
    const colorWhite = [255, 255, 255];
    const colorBlack = [0, 0, 0];
    const colorRed = [255, 0, 0];
    const colorYellow = [255, 255, 0];
    const colorGreen = [0, 255, 0];
    const colorBlue = [0, 0, 255];
    const availableColors = [];
    
    availableColors.push({ color: colorBlack, name: 'black' });
    availableColors.push({ color: colorWhite, name: 'white' });
    if (colorScheme === 1 || colorScheme === 3 || colorScheme === 4) {
      availableColors.push({ color: colorRed, name: 'red' });
    }
    if (colorScheme === 2 || colorScheme === 3 || colorScheme === 4) {
      availableColors.push({ color: colorYellow, name: 'yellow' });
    }
    if (colorScheme === 4) {
      availableColors.push({ color: colorGreen, name: 'green' });
      availableColors.push({ color: colorBlue, name: 'blue' });
    }
    
    let minDist = Infinity;
    let nearestColor = 'white';
    for (const colorInfo of availableColors) {
      const dist = Math.sqrt(
        Math.pow(r - colorInfo.color[0], 2) +
        Math.pow(g - colorInfo.color[1], 2) +
        Math.pow(b - colorInfo.color[2], 2)
      );
      if (dist < minDist) {
        minDist = dist;
        nearestColor = colorInfo.name;
      }
    }
    return nearestColor;
  }

  /**
   * Find nearest color RGB array for dithering
   * @param {number} r - Red component (0-255)
   * @param {number} g - Green component (0-255)
   * @param {number} b - Blue component (0-255)
   * @param {number} colorScheme - Color scheme (0-6)
   * @returns {Array} RGB array [r, g, b] of nearest color
   */
  findNearestColor(r, g, b, colorScheme) {
    if (colorScheme === 6) {
      const y = 0.299 * r + 0.587 * g + 0.114 * b;
      const lev = Math.min(15, Math.max(0, Math.round((y * 15) / 255)));
      const v = Math.round((lev * 255) / 15);
      return [v, v, v];
    }
    if (colorScheme === 5) {
      const gray = (r + g + b) / 3;
      if (gray < 64) {
        return [0, 0, 0];
      } else if (gray < 128) {
        return [85, 85, 85];
      } else if (gray < 192) {
        return [170, 170, 170];
      } else {
        return [255, 255, 255];
      }
    }
    const colorWhite = [255, 255, 255];
    const colorBlack = [0, 0, 0];
    const colorRed = [255, 0, 0];
    const colorYellow = [255, 255, 0];
    const colorGreen = [0, 255, 0];
    const colorBlue = [0, 0, 255];
    const availableColors = [];
    availableColors.push({ color: colorBlack, name: 'black' });
    availableColors.push({ color: colorWhite, name: 'white' });
    if (colorScheme === 1 || colorScheme === 3 || colorScheme === 4) {
      availableColors.push({ color: colorRed, name: 'red' });
    }
    if (colorScheme === 2 || colorScheme === 3 || colorScheme === 4) {
      availableColors.push({ color: colorYellow, name: 'yellow' });
    }
    if (colorScheme === 4) {
      availableColors.push({ color: colorGreen, name: 'green' });
      availableColors.push({ color: colorBlue, name: 'blue' });
    }
    let minDist = Infinity;
    let nearestColor = colorWhite;
    for (const colorInfo of availableColors) {
      const dist = Math.sqrt((r - colorInfo.color[0]) ** 2 + (g - colorInfo.color[1]) ** 2 + (b - colorInfo.color[2]) ** 2);
      if (dist < minDist) {
        minDist = dist;
        nearestColor = colorInfo.color;
      }
    }
    return nearestColor;
  }

  /**
   * Apply dithering to canvas context
   * @param {CanvasRenderingContext2D} ctx - Canvas 2D context
   * @param {number} width - Canvas width
   * @param {number} height - Canvas height
   * @param {number} colorScheme - Color scheme (0-6)
   * @param {string} ditheringType - Dithering algorithm ('floyd-steinberg', 'atkinson', 'stucki', 'sierra', 'sierra-lite', 'burkes', 'jarvis-judice-ninke')
   */
  applyDithering(ctx, width, height, colorScheme, ditheringType) {
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data;
    const errorsR = new Array(width * height).fill(0);
    const errorsG = new Array(width * height).fill(0);
    const errorsB = new Array(width * height).fill(0);

    const clamp = (value) => Math.max(0, Math.min(255, value));

    const setPixelError = (x, y, errR, errG, errB, factor) => {
      if (x < 0 || x >= width || y < 0 || y >= height) return;
      const index = y * width + x;
      errorsR[index] += errR * factor;
      errorsG[index] += errG * factor;
      errorsB[index] += errB * factor;
    };

    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const index = y * width + x;
        const dataIndex = index * 4;
        const oldR = clamp(data[dataIndex] + errorsR[index]);
        const oldG = clamp(data[dataIndex + 1] + errorsG[index]);
        const oldB = clamp(data[dataIndex + 2] + errorsB[index]);
        const [newR, newG, newB] = this.findNearestColor(oldR, oldG, oldB, colorScheme);
        data[dataIndex] = newR;
        data[dataIndex + 1] = newG;
        data[dataIndex + 2] = newB;
        const errR = oldR - newR;
        const errG = oldG - newG;
        const errB = oldB - newB;

        switch (ditheringType) {
          case 'floyd-steinberg':
            setPixelError(x + 1, y, errR, errG, errB, 7 / 16);
            setPixelError(x - 1, y + 1, errR, errG, errB, 3 / 16);
            setPixelError(x, y + 1, errR, errG, errB, 5 / 16);
            setPixelError(x + 1, y + 1, errR, errG, errB, 1 / 16);
            break;
          case 'atkinson':
            setPixelError(x + 1, y, errR, errG, errB, 1 / 8);
            setPixelError(x + 2, y, errR, errG, errB, 1 / 8);
            setPixelError(x - 1, y + 1, errR, errG, errB, 1 / 8);
            setPixelError(x, y + 1, errR, errG, errB, 1 / 8);
            setPixelError(x + 1, y + 1, errR, errG, errB, 1 / 8);
            setPixelError(x, y + 2, errR, errG, errB, 1 / 8);
            break;
          case 'stucki':
            setPixelError(x + 1, y, errR, errG, errB, 42 / 200);
            setPixelError(x + 2, y, errR, errG, errB, 26 / 200);
            setPixelError(x - 2, y + 1, errR, errG, errB, 8 / 200);
            setPixelError(x - 1, y + 1, errR, errG, errB, 24 / 200);
            setPixelError(x, y + 1, errR, errG, errB, 30 / 200);
            setPixelError(x + 1, y + 1, errR, errG, errB, 16 / 200);
            setPixelError(x + 2, y + 1, errR, errG, errB, 12 / 200);
            setPixelError(x - 2, y + 2, errR, errG, errB, 2 / 200);
            setPixelError(x - 1, y + 2, errR, errG, errB, 4 / 200);
            setPixelError(x, y + 2, errR, errG, errB, 2 / 200);
            setPixelError(x + 1, y + 2, errR, errG, errB, 4 / 200);
            setPixelError(x + 2, y + 2, errR, errG, errB, 2 / 200);
            break;
          case 'sierra':
            setPixelError(x + 1, y, errR, errG, errB, 5 / 32);
            setPixelError(x + 2, y, errR, errG, errB, 3 / 32);
            setPixelError(x - 2, y + 1, errR, errG, errB, 2 / 32);
            setPixelError(x - 1, y + 1, errR, errG, errB, 4 / 32);
            setPixelError(x, y + 1, errR, errG, errB, 3 / 32);
            setPixelError(x + 1, y + 1, errR, errG, errB, 2 / 32);
            setPixelError(x + 2, y + 1, errR, errG, errB, 2 / 32);
            setPixelError(x - 1, y + 2, errR, errG, errB, 2 / 32);
            setPixelError(x, y + 2, errR, errG, errB, 1 / 32);
            setPixelError(x + 1, y + 2, errR, errG, errB, 1 / 32);
            break;
          case 'sierra-lite':
            setPixelError(x + 1, y, errR, errG, errB, 2 / 4);
            setPixelError(x - 1, y + 1, errR, errG, errB, 1 / 4);
            setPixelError(x, y + 1, errR, errG, errB, 1 / 4);
            break;
          case 'burkes':
            setPixelError(x + 1, y, errR, errG, errB, 32 / 200);
            setPixelError(x + 2, y, errR, errG, errB, 12 / 200);
            setPixelError(x - 2, y + 1, errR, errG, errB, 5 / 200);
            setPixelError(x - 1, y + 1, errR, errG, errB, 12 / 200);
            setPixelError(x, y + 1, errR, errG, errB, 26 / 200);
            setPixelError(x + 1, y + 1, errR, errG, errB, 12 / 200);
            setPixelError(x + 2, y + 1, errR, errG, errB, 5 / 200);
            break;
          case 'jarvis-judice-ninke':
            setPixelError(x + 1, y, errR, errG, errB, 7 / 48);
            setPixelError(x + 2, y, errR, errG, errB, 5 / 48);
            setPixelError(x - 2, y + 1, errR, errG, errB, 3 / 48);
            setPixelError(x - 1, y + 1, errR, errG, errB, 5 / 48);
            setPixelError(x, y + 1, errR, errG, errB, 7 / 48);
            setPixelError(x + 1, y + 1, errR, errG, errB, 5 / 48);
            setPixelError(x + 2, y + 1, errR, errG, errB, 3 / 48);
            setPixelError(x - 2, y + 2, errR, errG, errB, 1 / 48);
            setPixelError(x - 1, y + 2, errR, errG, errB, 3 / 48);
            setPixelError(x, y + 2, errR, errG, errB, 5 / 48);
            setPixelError(x + 1, y + 2, errR, errG, errB, 3 / 48);
            setPixelError(x + 2, y + 2, errR, errG, errB, 1 / 48);
            break;
        }
      }
    }
    ctx.putImageData(imageData, 0, 0);
  }

  /**
   * Encode canvas to byte array for display
   * @param {HTMLCanvasElement} canvas - Canvas element
   * @param {number} colorScheme - Color scheme (0-6)
   * @param {number} rotation - Display rotation (0=0°, 1=90°, 2=180°, 3=270°)
   * @param {number} originalWidth - Original width before rotation
   * @param {number} originalHeight - Original height before rotation
   * @returns {Array} Byte array representing the image
   */
  encodeCanvasToByteData(canvas, colorScheme, rotation = 0, originalWidth = null, originalHeight = null) {
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    let imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    let pixels = imageData.data;
    let imageWidth = imageData.width;
    let imageHeight = imageData.height;
    
    // Handle rotation if needed
    if (rotation === 1 || rotation === 3) {
      const origWidth = originalWidth || imageHeight;
      const origHeight = originalHeight || imageWidth;
      const rotatedPixels = new Uint8ClampedArray(origWidth * origHeight * 4);
      
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const srcIndex = (y * imageWidth + x) * 4;
          let dstX, dstY;
          if (rotation === 1) {
            dstX = imageHeight - 1 - y;
            dstY = x;
          } else {
            dstX = y;
            dstY = imageWidth - 1 - x;
          }
          const dstIndex = (dstY * origWidth + dstX) * 4;
          rotatedPixels[dstIndex] = pixels[srcIndex];
          rotatedPixels[dstIndex + 1] = pixels[srcIndex + 1];
          rotatedPixels[dstIndex + 2] = pixels[srcIndex + 2];
          rotatedPixels[dstIndex + 3] = pixels[srcIndex + 3];
        }
      }
      pixels = rotatedPixels;
      imageWidth = origWidth;
      imageHeight = origHeight;
    } else if (rotation === 2) {
      const origWidth = originalWidth || imageWidth;
      const origHeight = originalHeight || imageHeight;
      const rotatedPixels = new Uint8ClampedArray(origWidth * origHeight * 4);
      
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const srcIndex = (y * imageWidth + x) * 4;
          const dstX = imageWidth - 1 - x;
          const dstY = imageHeight - 1 - y;
          const dstIndex = (dstY * origWidth + dstX) * 4;
          rotatedPixels[dstIndex] = pixels[srcIndex];
          rotatedPixels[dstIndex + 1] = pixels[srcIndex + 1];
          rotatedPixels[dstIndex + 2] = pixels[srcIndex + 2];
          rotatedPixels[dstIndex + 3] = pixels[srcIndex + 3];
        }
      }
      pixels = rotatedPixels;
      imageWidth = origWidth;
      imageHeight = origHeight;
    }
    
    const byteData = [];
    
    if (colorScheme === 4) {
      // 6-color scheme: 2 pixels per byte (nibbles)
      let currentByte = 0;
      let nibblePosition = 1;
      
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const i = (y * imageWidth + x) * 4;
          const r = pixels[i];
          const g = pixels[i + 1];
          const b = pixels[i + 2];
          const color = this.detectColor(r, g, b, colorScheme);
          let colorValue = 0;
          if (color === 'black') colorValue = 0;
          else if (color === 'white') colorValue = 1;
          else if (color === 'yellow') colorValue = 2;
          else if (color === 'red') colorValue = 3;
          else if (color === 'green') colorValue = 6;
          else if (color === 'blue') colorValue = 5;
          
          if (nibblePosition === 1) {
            currentByte = (colorValue << 4);
            nibblePosition = 0;
          } else {
            currentByte |= colorValue;
            byteData.push(currentByte);
            currentByte = 0;
            nibblePosition = 1;
          }
        }
      }
      if (nibblePosition === 0) {
        byteData.push(currentByte);
      }
    } else if (colorScheme === 6) {
      // 16 gray (4bpp): same nibble order as 6-color — even x = high nibble, odd x = low; 0=black .. 15=white (Seeed TFT_GRAY_*).
      let currentByte = 0;
      let nibblePosition = 1;
      const grayLevel = (rr, gg, bb) => {
        const y = 0.299 * rr + 0.587 * gg + 0.114 * bb;
        return Math.min(15, Math.max(0, Math.round((y * 15) / 255)));
      };
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const i = (y * imageWidth + x) * 4;
          const level = grayLevel(pixels[i], pixels[i + 1], pixels[i + 2]);
          if (nibblePosition === 1) {
            currentByte = (level << 4);
            nibblePosition = 0;
          } else {
            currentByte |= level;
            byteData.push(currentByte);
            currentByte = 0;
            nibblePosition = 1;
          }
        }
      }
      if (nibblePosition === 0) {
        byteData.push(currentByte);
      }
    } else if (colorScheme === 5) {
      // 4 grayscale: 4 pixels per byte
      let currentByte = 0;
      let pixelInByte = 0;
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const i = (y * imageWidth + x) * 4;
          const r = pixels[i];
          const g = pixels[i + 1];
          const b = pixels[i + 2];
          const gray = (r + g + b) / 3;
          let grayLevel;
          if (gray < 64) grayLevel = 0;
          else if (gray < 128) grayLevel = 1;
          else if (gray < 192) grayLevel = 2;
          else grayLevel = 3;
          
          currentByte |= (grayLevel << (6 - pixelInByte * 2));
          pixelInByte++;
          if (pixelInByte >= 4) {
            byteData.push(currentByte);
            currentByte = 0;
            pixelInByte = 0;
          }
        }
      }
      if (pixelInByte > 0) {
        byteData.push(currentByte);
      }
    } else if (colorScheme === 1 || colorScheme === 2) {
      // B/W + Red or B/W + Yellow: 2 bitplanes
      const byteDataPlane1 = [];
      const byteDataPlane2 = [];
      let currentByte1 = 0;
      let currentByte2 = 0;
      let bitPosition = 7;
      
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const i = (y * imageWidth + x) * 4;
          const r = pixels[i];
          const g = pixels[i + 1];
          const b = pixels[i + 2];
          const color = this.detectColor(r, g, b, colorScheme);
          if (color === 'white') {
            currentByte1 |= (1 << bitPosition);
          } else if (color === 'red') {
            currentByte1 |= (1 << bitPosition);
            currentByte2 |= (1 << bitPosition);
          } else if (color === 'yellow') {
            currentByte2 |= (1 << bitPosition);
          }
          bitPosition--;
          if (bitPosition < 0) {
            byteDataPlane1.push(currentByte1);
            byteDataPlane2.push(currentByte2);
            currentByte1 = 0;
            currentByte2 = 0;
            bitPosition = 7;
          }
        }
      }
      
      if (bitPosition !== 7) {
        byteDataPlane1.push(currentByte1);
        byteDataPlane2.push(currentByte2);
      }
      byteData.push(...byteDataPlane1);
      byteData.push(...byteDataPlane2);
    } else if (colorScheme === 3) {
      // B/W + Red + Yellow: 4 pixels per byte
      let currentByte = 0;
      let pixelInByte = 0;
      
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const i = (y * imageWidth + x) * 4;
          const r = pixels[i];
          const g = pixels[i + 1];
          const b = pixels[i + 2];
          const color = this.detectColor(r, g, b, colorScheme);
          let colorValue = 0;
          if (color === 'black') colorValue = 0;
          else if (color === 'white') colorValue = 1;
          else if (color === 'yellow') colorValue = 2;
          else if (color === 'red') colorValue = 3;
          
          currentByte |= (colorValue << (6 - pixelInByte * 2));
          pixelInByte++;
          if (pixelInByte >= 4) {
            byteData.push(currentByte);
            currentByte = 0;
            pixelInByte = 0;
          }
        }
      }
      if (pixelInByte > 0) {
        byteData.push(currentByte);
      }
    } else {
      // Monochrome: 1 bit per pixel
      let currentByte = 0;
      let bitPosition = 7;
      
      for (let y = 0; y < imageHeight; y++) {
        for (let x = 0; x < imageWidth; x++) {
          const i = (y * imageWidth + x) * 4;
          const r = pixels[i];
          const g = pixels[i + 1];
          const b = pixels[i + 2];
          const gray = (r + g + b) / 3;
          if (gray > 128) {
            currentByte |= (1 << bitPosition);
          }
          bitPosition--;
          if (bitPosition < 0) {
            byteData.push(currentByte);
            currentByte = 0;
            bitPosition = 7;
          }
        }
      }
      if (bitPosition !== 7) {
        byteData.push(currentByte);
      }
    }
    
    return byteData;
  }

  /**
   * Send canvas image to display via direct write
   * @param {HTMLCanvasElement} canvas - Canvas element
   * @param {number} colorScheme - Color scheme (0-6)
   * @param {Object} options - Options
   * @param {number} options.rotation - Display rotation (0-3)
   * @param {number} options.originalWidth - Original width before rotation
   * @param {number} options.originalHeight - Original height before rotation
   * @param {boolean} options.useFastRefresh - Use fast/partial refresh
   * @param {number} options.transmissionModes - Transmission modes bitfield (bit 1 = ZIP compression support)
   * @param {Function} options.onProgress - Progress callback (progress, total)
   * @param {Function} options.onComplete - Completion callback (success, error)
   * @param {Function} options.onStatusChange - Status change callback (message)
   */
  async sendCanvasToDisplay(canvas, colorScheme, options = {}) {
    if (!this.isConnected) {
      throw new Error('Not connected');
    }
    
    if (this.directWriteState && this.directWriteState.active) {
      throw new Error('Direct write already in progress');
    }
    
    const {
      rotation = 0,
      originalWidth = null,
      originalHeight = null,
      useFastRefresh = false,
      transmissionModes = null,
      onProgress = null,
      onComplete = null,
      onStatusChange = null
    } = options;
    
    // Calculate chunk size based on encryption status
    // Encryption adds 31 bytes overhead: 2 (header) + 16 (nonce) + 1 (length) + 12 (tag)
    // Use a safe MTU of 185 bytes for encrypted packets (some BLE stacks negotiate lower MTUs)
    // Plaintext chunk size = 185 - 31 = 154 bytes when encrypted
    // When not encrypted, use the full 230 bytes
    const ENCRYPTION_OVERHEAD = 31; // 2 (header) + 16 (nonce) + 1 (length) + 12 (tag)
    const MAX_ENCRYPTED_PACKET_SIZE = 185; // Safe MTU size for encrypted packets
    const DIRECT_WRITE_CHUNK_SIZE_UNENCRYPTED = 230;
    const DIRECT_WRITE_CHUNK_SIZE_ENCRYPTED = MAX_ENCRYPTED_PACKET_SIZE - ENCRYPTION_OVERHEAD; // 154 bytes
    const DIRECT_WRITE_CHUNK_SIZE = (this.encryptionSession.authenticated) 
      ? DIRECT_WRITE_CHUNK_SIZE_ENCRYPTED 
      : DIRECT_WRITE_CHUNK_SIZE_UNENCRYPTED;
    const DIRECT_WRITE_PIPELINE_SIZE = 1;
    const TRANSMISSION_MODE_ZIPXL = 0x01;
    const TRANSMISSION_MODE_ZIP = 0x02;
    const MAX_COMPRESSED_SIZE_STD = 54 * 1024;
    const MAX_COMPRESSED_SIZE_ZIPXL = 512 * 1024;
    
    if (this.encryptionSession.authenticated) {
      this.log(`Encryption enabled: Using reduced chunk size ${DIRECT_WRITE_CHUNK_SIZE} bytes (encrypted size: ${DIRECT_WRITE_CHUNK_SIZE + ENCRYPTION_OVERHEAD} bytes)`, 'info');
    }
    
    // Initialize direct write state
    this.directWriteState = {
      active: true,
      compressed: false,
      chunks: [],
      chunkIndex: 0,
      pendingAcks: 0,
      uploadStartTime: Date.now(),
      uploadEndTime: null,
      refreshStartTime: null,
      onProgress: onProgress,
      onComplete: onComplete,
      onStatusChange: onStatusChange,
      useFastRefresh: useFastRefresh,
      chunkSize: DIRECT_WRITE_CHUNK_SIZE,
      pipelineSize: DIRECT_WRITE_PIPELINE_SIZE
    };
    
    try {
      // Encode canvas to bytes
      const byteData = this.encodeCanvasToByteData(canvas, colorScheme, rotation, originalWidth, originalHeight);
      const uncompressedSize = byteData.length;
      const byteDataUint8 = new Uint8Array(byteData);
      
      const supportsZipCompression = transmissionModes !== null && transmissionModes !== undefined &&
                                     (transmissionModes & TRANSMISSION_MODE_ZIP) !== 0;
      const maxCompressedSize = supportsZipCompression
        ? (((transmissionModes & TRANSMISSION_MODE_ZIPXL) !== 0) ? MAX_COMPRESSED_SIZE_ZIPXL : MAX_COMPRESSED_SIZE_STD)
        : 0;
      
      // Try compression if pako is available AND device supports ZIP compression
      let compressedBytes = null;
      if (supportsZipCompression && typeof pako !== 'undefined') {
        try {
          compressedBytes = pako.deflate(byteDataUint8, {
            level: 9,
            windowBits: 12
          });
        } catch (e) {
          this.log('Compression failed, using uncompressed: ' + e.message, 'warning');
        }
      } else if (!supportsZipCompression && typeof pako !== 'undefined') {
        this.log('Device does not support ZIP compression (transmission_modes ZIP not set), using uncompressed', 'info');
      }
      
      const useCompressed = supportsZipCompression && compressedBytes && compressedBytes.length <= maxCompressedSize;
      
      if (useCompressed) {
        this.directWriteState.compressed = true;
        this.directWriteState.data = Array.from(compressedBytes);
        this.log(`Using compressed upload: ${uncompressedSize} bytes uncompressed, ${compressedBytes.length} bytes compressed`, 'info');
      } else {
        this.directWriteState.compressed = false;
        this.directWriteState.data = byteData;
        this.log(`Using uncompressed upload: ${uncompressedSize} bytes`, 'info');
      }
      
      // Chunk the data
      const dataToSend = this.directWriteState.data;
      for (let i = 0; i < dataToSend.length; i += DIRECT_WRITE_CHUNK_SIZE) {
        const chunk = dataToSend.slice(i, i + DIRECT_WRITE_CHUNK_SIZE);
        this.directWriteState.chunks.push(chunk);
      }
      
      if (onStatusChange) {
        onStatusChange(`Starting upload: ${canvas.width}x${canvas.height} pixels, ${this.directWriteState.chunks.length} chunks`);
      }
      
      // Send start command
      if (useCompressed) {
        const startPayload = new Uint8Array(4 + compressedBytes.length);
        startPayload[0] = uncompressedSize & 0xFF;
        startPayload[1] = (uncompressedSize >> 8) & 0xFF;
        startPayload[2] = (uncompressedSize >> 16) & 0xFF;
        startPayload[3] = (uncompressedSize >> 24) & 0xFF;
        startPayload.set(compressedBytes, 4);
        
        // Account for encryption overhead when calculating max start payload size
        // When encrypted: maxStartPayload = MAX_ENCRYPTED_PACKET_SIZE - ENCRYPTION_OVERHEAD
        // When not encrypted: use original 200 bytes
        const maxStartPayload = (this.encryptionSession.authenticated)
          ? MAX_ENCRYPTED_PACKET_SIZE - ENCRYPTION_OVERHEAD  // 185 - 31 = 154 bytes
          : 200;
        if (startPayload.length <= maxStartPayload) {
          const startPayloadHex = this.bytesToHex(startPayload).replace(/\s+/g, '');
          await this.sendHexCommand('0070' + startPayloadHex);
          this.directWriteState.chunkIndex = this.directWriteState.chunks.length;
          this.directWriteState.pendingAcks = 0;
        } else {
          const headerHex = this.bytesToHex(startPayload.slice(0, 4)).replace(/\s+/g, '');
          const maxCompressedInStart = maxStartPayload - 4;
          const firstChunkData = startPayload.slice(4, 4 + Math.min(maxCompressedInStart, DIRECT_WRITE_CHUNK_SIZE));
          const firstChunkHex = this.bytesToHex(firstChunkData).replace(/\s+/g, '');
          await this.sendHexCommand('0070' + headerHex + firstChunkHex);
          const firstChunkBytesSent = firstChunkData.length;
          if (this.directWriteState.chunks.length > 0) {
            const firstChunkSize = this.directWriteState.chunks[0].length;
            if (firstChunkBytesSent >= firstChunkSize) {
              this.directWriteState.chunkIndex = 1;
            } else {
              this.directWriteState.chunks[0] = this.directWriteState.chunks[0].slice(firstChunkBytesSent);
              this.directWriteState.chunkIndex = 0;
            }
          }
        }
        } else {
          await this.sendHexCommand('0070');
        }
      
      // Don't send chunks yet - wait for 0070 response from device
      // The notification handler will call sendNextDirectWriteChunk() when it receives 0070
      
    } catch (error) {
      this.directWriteState.active = false;
      if (onComplete) {
        onComplete(false, error);
      }
      throw error;
    }
  }

  /**
   * Send next direct write chunk (internal)
   */
  sendNextDirectWriteChunk() {
    if (!this.directWriteState || !this.directWriteState.active) return;
    
    const state = this.directWriteState;
    
    while (state.active &&
           state.chunkIndex < state.chunks.length &&
           state.pendingAcks < state.pipelineSize) {
      
      const chunk = state.chunks[state.chunkIndex];
      const chunkHex = this.bytesToHex(chunk).replace(/\s+/g, '');
      
      const progress = Math.floor((state.chunkIndex / state.chunks.length) * 100);
      if (state.chunkIndex % 10 === 0 || state.chunkIndex === state.chunks.length - 1) {
        if (state.onStatusChange) {
          state.onStatusChange(`Uploading: ${progress}% (${state.chunkIndex + 1}/${state.chunks.length} chunks)`);
        }
        if (state.onProgress) {
          state.onProgress(state.chunkIndex + 1, state.chunks.length);
        }
      }
      
      this.sendHexCommand('0071' + chunkHex).catch(err => {
        this.log('Error sending chunk: ' + err.message, 'error');
      });
      state.chunkIndex++;
      state.pendingAcks++;
    }
    
    if (state.chunkIndex >= state.chunks.length && state.pendingAcks === 0) {
      state.uploadEndTime = Date.now();
      if (!state.refreshStartTime) {
        state.refreshStartTime = state.uploadEndTime;
      }
      const uploadTime = state.uploadStartTime
        ? ((state.uploadEndTime - state.uploadStartTime) / 1000).toFixed(2)
        : "?";
      this.log(`All chunks sent (upload took ${uploadTime}s), sending end command...`, 'info');
      if (state.onStatusChange) {
        state.onStatusChange(`Upload complete (${uploadTime}s), refreshing display...`);
      }
      
      if (state.useFastRefresh) {
        this.sendHexCommand('007201');
      } else {
        this.sendHexCommand('0072');
      }
    }
  }

  /**
   * Handle direct write notification (call this from onNotification)
   * @param {Uint8Array} bytes - Notification bytes
   * @param {string} hexString - Hex string representation
   * @returns {boolean} True if handled
   */
  handleDirectWriteNotification(bytes, hexString) {
    if (!this.directWriteState || !this.directWriteState.active) {
      return false;
    }
    
    if (bytes.length < 2) {
      this.log(`Direct write notification too short: ${bytes.length} bytes`, 'warning');
      return false;
    }
    
    // Parse command - handle both byte orders (00 70 and 70 00)
    const cmd1 = bytes[0];
    const cmd2 = bytes[1];
    let responseType = null;
    
    // Check for 00 XX format
    if (cmd1 === 0x00 && (cmd2 === 0x70 || cmd2 === 0x71 || cmd2 === 0x72 || cmd2 === 0x73 || cmd2 === 0x74)) {
      responseType = cmd2;
    }
    // Check for XX 00 format (reversed byte order)
    else if (cmd2 === 0x00 && (cmd1 === 0x70 || cmd1 === 0x71 || cmd1 === 0x72 || cmd1 === 0x73 || cmd1 === 0x74)) {
      responseType = cmd1;
    }
    
    // Also check hex string format (for compatibility with display page parsing)
    if (responseType === null && hexString) {
      const cleanHex = hexString.replace(/\s+/g, '').toUpperCase();
      if (cleanHex.length >= 4) {
        const cmdHex = cleanHex.substring(0, 4);
        // Check for 0070, 0071, 0072, 0073, 0074
        if (cmdHex === '0070' || cmdHex === '0071' || cmdHex === '0072' || cmdHex === '0073' || cmdHex === '0074') {
          responseType = parseInt(cmdHex.substring(2, 4), 16);
        }
        // Check for 7000, 7100, 7200, 7300, 7400 (reversed)
        else if (cmdHex === '7000' || cmdHex === '7100' || cmdHex === '7200' || cmdHex === '7300' || cmdHex === '7400') {
          responseType = parseInt(cmdHex.substring(0, 2), 16);
        }
      }
    }
    
    if (responseType === null) {
      return false;
    }
    
    // Handle direct write responses
    if (responseType === 0x70) {
      // Direct write started - device acknowledged the start command
      this.log('Direct write started, sending data chunks...', 'success');
      this.directWriteState.pendingAcks = 0;
      // Now send chunks (or end command if all data was in start payload)
      this.sendNextDirectWriteChunk();
      return true;
    } else if (responseType === 0x71) {
      // Chunk ACK
      if (this.directWriteState.active) {
        this.directWriteState.pendingAcks = Math.max(0, this.directWriteState.pendingAcks - 1);
        // Continue sending chunks
        this.sendNextDirectWriteChunk();
        return true;
      }
    } else if (responseType === 0x72) {
      // End command ACK
      if (!this.directWriteState.refreshStartTime) {
        this.directWriteState.refreshStartTime = Date.now();
        this.log('Display is refreshing...', 'info');
      }
      return true;
    } else if (responseType === 0x73) {
      // Refresh complete
      const refreshEndTime = Date.now();
      let refreshTime = "?";
      if (this.directWriteState.refreshStartTime) {
        refreshTime = ((refreshEndTime - this.directWriteState.refreshStartTime) / 1000).toFixed(2);
      }
      const uploadTime = this.directWriteState.uploadEndTime && this.directWriteState.uploadStartTime
        ? ((this.directWriteState.uploadEndTime - this.directWriteState.uploadStartTime) / 1000).toFixed(2)
        : "?";
      const totalTime = this.directWriteState.uploadStartTime
        ? ((refreshEndTime - this.directWriteState.uploadStartTime) / 1000).toFixed(2)
        : "?";
      this.log(`Direct write completed! Upload: ${uploadTime}s, Refresh: ${refreshTime}s, Total: ${totalTime}s`, 'success');
      if (this.directWriteState.onStatusChange) {
        this.directWriteState.onStatusChange(`Upload completed! Upload: ${uploadTime}s, Refresh: ${refreshTime}s`);
      }
      
      // Reset state
      const wasActive = this.directWriteState.active;
      this.directWriteState.active = false;
      this.directWriteState.data = null;
      this.directWriteState.chunks = [];
      this.directWriteState.chunkIndex = 0;
      this.directWriteState.pendingAcks = 0;
      this.directWriteState.uploadStartTime = null;
      this.directWriteState.uploadEndTime = null;
      this.directWriteState.refreshStartTime = null;
      
      if (wasActive && this.directWriteState.onComplete) {
        this.directWriteState.onComplete(true, null);
      }
      return true;
    } else if (responseType === 0x74) {
      // Refresh timeout
      this.log('Display refresh timed out', 'error');
      const wasActive = this.directWriteState.active;
      this.directWriteState.active = false;
      this.directWriteState.data = null;
      this.directWriteState.chunks = [];
      this.directWriteState.chunkIndex = 0;
      this.directWriteState.pendingAcks = 0;
      this.directWriteState.uploadStartTime = null;
      this.directWriteState.uploadEndTime = null;
      this.directWriteState.refreshStartTime = null;
      
      if (wasActive && this.directWriteState.onComplete) {
        this.directWriteState.onComplete(false, new Error('Display refresh timed out'));
      }
      return true;
    }
    
    return false;
  }
}

/**
 * DFU (Device Firmware Update) support classes and functions
 */

// DFU Constants
const DFU_BLOCK_DATA_SIZE = 4096;
const DFU_BLOCK_PART_DATA_SIZE = 230;
const DFU_BLOCK_REQ_PARTS_BYTES = 6;

/**
 * BlockRequest class for parsing DFU block requests
 */
class BlockRequest {
  constructor(hexString) {
    this.checksum = this.fromHex(hexString.substring(0, 2));
    this.ver = BigInt("0x" + this.reverseEndian(hexString.substring(2, 18)));
    this.blockId = this.fromHex(hexString.substring(18, 20));
    this.type = this.fromHex(hexString.substring(20, 22));
    const requestedPartsHex = hexString.substring(22, 22 + DFU_BLOCK_REQ_PARTS_BYTES * 2);
    this.requestedParts = this.hexToBitField(requestedPartsHex);
  }
  
  fromHex(hexStr) {
    return parseInt(hexStr, 16);
  }
  
  reverseEndian(hex) {
    const bytes = hex.match(/.{2}/g);
    return bytes ? bytes.reverse().join('') : '';
  }
  
  hexToBitField(hexStr) {
    const bitField = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      const byte = parseInt(hexStr.substring(i, i + 2), 16);
      for (let bit = 7; bit >= 0; bit--) {
        bitField.push((byte >> bit) & 1);
      }
    }
    return bitField;
  }
  
  display() {
    console.log(`Checksum: ${this.checksum}, Version: ${this.ver.toString(16).toUpperCase()}, Block ID: ${this.blockId}, Type: ${this.type}, Requested Parts: ${this.requestedParts.join('')}`);
  }
}

/**
 * BlockPart class for creating DFU block part packets
 */
class BlockPart {
  constructor(blockId, blockPart, dataSlice) {
    this.blockId = blockId;
    this.blockPart = blockPart;
    this.data = dataSlice;
    this.buffer = new Uint8Array(3 + DFU_BLOCK_PART_DATA_SIZE);
    this.buffer[1] = blockId;
    this.buffer[2] = blockPart;
    for (let i = 0; i < DFU_BLOCK_PART_DATA_SIZE; i++) {
      this.buffer[3 + i] = dataSlice[i] || 0;
    }
    this.addCRC();
  }
  
  addCRC() {
    let total = 0;
    for (let i = 1; i < this.buffer.length; i++) {
      total += this.buffer[i];
    }
    this.buffer[0] = total & 0xFF;
  }
  
  toHexString() {
    return Array.from(this.buffer).map(byte => byte.toString(16).padStart(2, '0').toUpperCase()).join('');
  }
}

/**
 * Premade hardware presets as simple-config IDs (driver / display / power).
 * `stem` matches legacy toolbox preset filenames without .json for ?config= URLs.
 */
const PREMADE_SIMPLE_PRESETS = [
  { stem: 'nrf52840-en04', name: 'Seeed EN04 NRF 4.26', driverBoardId: 'en04', displayId: 'ep426-800x480', powerId: 'battery-2000' },
  { stem: 'nrf52840-en04-s6', name: 'Seeed EN04 NRF 7.3 Spectra6', driverBoardId: 'en04', displayId: 'ep73-spectra-800x480', powerId: 'battery-2000' },
  { stem: 'esp32-s3-ee04', name: 'Seeed EE04 ESP 4.26', driverBoardId: 'ee04', displayId: 'ep426-800x480', powerId: 'battery-2000' },
  { stem: 'esp32-s3-wspp', name: 'Waveshare ESP32-S3-PhotoPainter', driverBoardId: 'esp32-s3-wspp', displayId: 'ep73-spectra-800x480', powerId: 'battery-2000' },
  { stem: 'esp32-s3-bo', name: 'Seeed XIAO ESP32-S3 breakout 4.26', driverBoardId: 'esp32s3-xiao', displayId: 'ep426-800x480', powerId: 'battery-2000' },
  { stem: 'esp32-c6-bo', name: 'Seeed XIAO ESP32-C6 breakout 4.26', driverBoardId: 'esp32c6-xiao', displayId: 'ep426-800x480', powerId: 'battery-2000' },
  { stem: 'esp32-c3-bo', name: 'Seeed XIAO ESP32-C3 breakout 4.26', driverBoardId: 'esp32c3-xiao', displayId: 'ep426-800x480', powerId: 'battery-2000' },
  { stem: 'nrf52840-bo', name: 'Seeed XIAO NRF52840 breakout 4.26', driverBoardId: 'nrf52840-xiao', displayId: 'ep426-800x480', powerId: 'battery-2000' },
  { stem: 'xiao-75-c3', name: 'XIAO 75 C3', driverBoardId: 'xiao-75-c3', displayId: 'ep75-800x480', powerId: 'battery-2000' },
  { stem: 'xiao-75-s3-og', name: 'XIAO 75 S3 OG', driverBoardId: 'ee04', displayId: 'ep75-800x480', powerId: 'battery-2000' },
  { stem: 'reterminal-e1001', name: 'ReTerminal E1001', driverBoardId: 'reterminal-e1001', displayId: 'ep75-800x480', powerId: 'battery-2000' },
  { stem: 'reterminal-e1002', name: 'ReTerminal E1002', driverBoardId: 'reterminal-e1002', displayId: 'ep73-spectra-800x480', powerId: 'battery-2000' }
];

function extractLegacyPremadeConfigStem(configParam) {
  if (!configParam || typeof configParam !== 'string') return '';
  const t = configParam.trim();
  const base = t.split(/[/\\]/).pop() || t;
  return base.replace(/\.json$/i, '');
}

/**
 * Map a legacy ?config= preset name or path to simple-config triple, or null.
 */
function getPremadeLegacySimpleTriple(configParam) {
  const stem = extractLegacyPremadeConfigStem(configParam).toLowerCase();
  if (!stem) return null;
  const p = PREMADE_SIMPLE_PRESETS.find((x) => x.stem.toLowerCase() === stem);
  if (!p) return null;
  return {
    driverBoardId: p.driverBoardId,
    displayId: p.displayId,
    powerId: p.powerId
  };
}

/**
 * Preset list for pages that use simple-config-presets.json (designer, battery).
 */
function getPremadeSimplePresets() {
  return PREMADE_SIMPLE_PRESETS.map((p) => ({
    name: p.name,
    driverBoardId: p.driverBoardId,
    displayId: p.displayId,
    powerId: p.powerId
  }));
}

function parseSimpleConfigPixelDimension(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number' && !Number.isNaN(value)) return value;
  const s = String(value).trim();
  if (s.startsWith('0x') || s.startsWith('0X')) {
    const n = parseInt(s, 16);
    return Number.isNaN(n) ? null : n;
  }
  const dec = parseInt(s, 10);
  return Number.isNaN(dec) ? null : dec;
}

/**
 * Read canvas size and color scheme for a display id from loaded simple-config-presets data.
 */
function getDisplayLayoutFromSimplePresetsDb(db, displayId) {
  if (!db || !db.displays || !displayId) return null;
  const d = db.displays.find((x) => x.id === displayId);
  if (!d || !d.config) return null;
  const w = parseSimpleConfigPixelDimension(d.config.pixel_width);
  const h = parseSimpleConfigPixelDimension(d.config.pixel_height);
  if (w === null || h === null) return null;
  const cs = parseInt(String(d.config.color_scheme != null ? d.config.color_scheme : '0'), 10);
  return {
    width: w,
    height: h,
    colorScheme: Number.isNaN(cs) ? 0 : cs
  };
}
