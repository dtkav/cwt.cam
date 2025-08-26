/**
 * CBOR Visualizer Library
 * Provides interactive visualization of CBOR data structures
 */

class CBORVisualizer {
    constructor() {
        this.currentByteMap = [];
        this.currentStructures = [];
    }

    /**
     * Main entry point to visualize CBOR data
     * @param {string} input - Base64 or hex encoded CBOR data
     * @param {Object} options - Visualization options
     * @returns {Object} Result object with success status and any errors
     */
    visualize(input, options = {}) {
        const {
            bytesContainer,
            structureContainer,
            onError = () => {},
            onHighlight = () => {},
            onClearHighlight = () => {}
        } = options;

        if (!input) {
            const error = 'Please enter a base64-encoded or hex-encoded CWT';
            onError(error);
            return { success: false, error };
        }

        try {
            // Decode the input
            const bytes = this.decodeInput(input);
            
            // Decode CBOR structure
            const decoder = new CBORVisualizationDecoder(Array.from(bytes), options);
            const result = decoder.decode();
            
            this.currentByteMap = result.byteMap;
            this.currentStructures = result.structures;

            // Display bytes if container provided
            if (bytesContainer) {
                this.displayBytes(bytes, bytesContainer, onHighlight, onClearHighlight);
            }
            
            // Display structure if container provided
            if (structureContainer) {
                this.displayStructure(result.structures, structureContainer, onHighlight, onClearHighlight);
            }

            return { 
                success: true, 
                bytes: bytes,
                structures: result.structures,
                byteMap: result.byteMap
            };
        } catch (e) {
            let errorMsg = e.message;
            if (e.message.includes('invalid character')) {
                errorMsg = 'Invalid base64 encoding. The input contains characters that are not valid base64. Please check that you have copied the entire token correctly.';
            }
            onError(errorMsg);
            return { success: false, error: errorMsg };
        }
    }

    /**
     * Decode input string (base64 or hex) to bytes
     */
    decodeInput(input) {
        // Remove all whitespace from input
        const cleanInput = input.trim().replace(/[\s\n\r\t]/g, '');
        
        // Detect format and decode accordingly
        if (/^[0-9A-Fa-f]+$/.test(cleanInput)) {
            // Hex string detected
            if (cleanInput.length % 2 !== 0) {
                throw new Error('Hex string must have an even number of characters');
            }
            
            // Convert hex to bytes
            const bytes = new Uint8Array(cleanInput.length / 2);
            for (let i = 0; i < cleanInput.length; i += 2) {
                bytes[i / 2] = parseInt(cleanInput.substr(i, 2), 16);
            }
            return bytes;
            
        } else {
            // Try base64 decoding
            let base64Input = cleanInput
                .replace(/-/g, '+')        // Convert URL-safe to standard
                .replace(/_/g, '/');       // Convert URL-safe to standard
            
            // Add padding if necessary
            while (base64Input.length % 4 !== 0) {
                base64Input += '=';
            }
            
            // Validate base64 characters
            if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64Input)) {
                throw new Error('Invalid input format. Expected base64 or hexadecimal string.');
            }
            
            // Decode base64
            const binaryString = atob(base64Input);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        }
    }

    /**
     * Display bytes with interactive highlighting
     */
    displayBytes(bytes, container, onHighlight, onClearHighlight) {
        container.innerHTML = '';
        
        // Create tree structure for bytes display
        this.createBytesTreeStructure(bytes, container, onHighlight, onClearHighlight);
    }
    
    /**
     * Create clean visual structure for bytes with COSE component separation
     */
    createBytesTreeStructure(bytes, container, onHighlight, onClearHighlight) {
        // Analyze COSE structure to find component boundaries
        const coseComponents = this.analyzeCOSEComponents(bytes);
        
        // Create visual sections with separation
        coseComponents.forEach((component, index) => {
            // Add visual separator between components
            if (index > 0) {
                const separator = document.createElement('div');
                separator.className = 'cbor-component-separator';
                separator.innerHTML = '';
                container.appendChild(separator);
            }
            
            // Add component label if needed
            if (component.label) {
                const label = document.createElement('div');
                label.className = 'cbor-bytes-tree-label';
                label.textContent = component.label;
                container.appendChild(label);
            }
            
            // Add component bytes
            const section = document.createElement('div');
            section.className = `cbor-bytes-tree-level cbor-bytes-${component.type}-level`;
            
            component.bytes.forEach((byteInfo, byteIndex) => {
                const byteElement = this.createByteElementForComponent(
                    byteInfo, component, byteIndex, onHighlight, onClearHighlight
                );
                section.appendChild(byteElement);
            });
            
            container.appendChild(section);
        });
    }
    
    /**
     * Analyze CBOR structure to identify COSE components cleanly
     */
    analyzeCOSEComponents(bytes) {
        const components = [];
        
        // Debug: log structure info
        console.log('=== DEBUGGING COSE COMPONENTS ===');
        console.log('Total structures:', this.currentStructures.length);
        this.currentStructures.forEach((s, i) => {
            console.log(`[${i}] indent:${s.indent} offset:${s.startOffset}-${s.endOffset} desc:"${s.description}"`);
        });
        
        // Find main COSE structure boundaries
        const coseArrayIndex = this.currentStructures.findIndex(s => 
            s.description && s.description.includes('COSE Structure Array')
        );
        
        console.log('COSE Array Index:', coseArrayIndex);
        
        if (coseArrayIndex >= 0) {
            const coseArrayElements = this.findCOSEArrayElements();
            console.log('COSE Array Elements:', coseArrayElements.length);
            coseArrayElements.forEach((elem, i) => {
                console.log(`  Element [${i}]:`, elem.description, `offset:${elem.startOffset}-${elem.endOffset}`);
            });
            
            // Component 1: COSE Tag and Array structure (before first header)
            const preambleBytes = this.extractCOSEPreamble(bytes);
            console.log('Preamble bytes count:', preambleBytes.length);
            if (preambleBytes.length > 0) {
                components.push({
                    type: 'preamble',
                    label: null, // No label for COSE tag + array
                    bytes: preambleBytes
                });
            }
            
            // Component 2: Protected Headers
            const protectedHeaderBytes = this.extractProtectedHeaders(bytes, coseArrayElements);
            console.log('Protected header bytes count:', protectedHeaderBytes.length);
            if (protectedHeaderBytes.length > 0) {
                components.push({
                    type: 'protected-headers',
                    label: '├─ Protected Headers:',
                    bytes: protectedHeaderBytes
                });
            }
            
            // Component 3: Unprotected Headers  
            const unprotectedHeaderBytes = this.extractUnprotectedHeaders(bytes, coseArrayElements);
            console.log('Unprotected header bytes count:', unprotectedHeaderBytes.length);
            if (unprotectedHeaderBytes.length > 0) {
                components.push({
                    type: 'unprotected-headers',
                    label: coseArrayElements.length === 4 ? '├─ Unprotected Headers:' : '└─ Unprotected Headers:',
                    bytes: unprotectedHeaderBytes
                });
            }
            
            // Determine COSE type and structure
            const coseType = this.determineCOSEType();
            console.log('COSE Type detected:', coseType);
            
            // Component 4: Payload/Ciphertext
            const payloadBytes = this.extractCOSEPayload(bytes);
            console.log('Payload bytes count:', payloadBytes.length);
            if (payloadBytes.length > 0) {
                let payloadLabel;
                if (coseType === 'COSE_Encrypt0' || coseType === 'COSE_Encrypt') {
                    payloadLabel = coseArrayElements.length === 4 ? '├─ Ciphertext:' : '└─ Ciphertext:';
                } else {
                    payloadLabel = coseArrayElements.length === 4 ? '├─ Payload:' : '└─ Payload:';
                }
                
                components.push({
                    type: 'payload', 
                    label: payloadLabel,
                    bytes: payloadBytes
                });
                
                // Component 5: Decrypted payload (if available for encryption types)
                if (coseType === 'COSE_Encrypt0' || coseType === 'COSE_Encrypt') {
                    const decryptedBytes = this.extractDecryptedPayload();
                    console.log('Decrypted bytes count:', decryptedBytes.length);
                    if (decryptedBytes.length > 0) {
                        components.push({
                            type: 'decrypted',
                            label: '└─ Decrypted Payload:',
                            bytes: decryptedBytes
                        });
                    }
                }
            }
            
            // Component 6: Signature/MAC (if present - only for Sign/Mac types)
            if (coseArrayElements.length === 4) {
                const signatureBytes = this.extractCOSESignature(bytes);
                console.log('Signature bytes count:', signatureBytes.length);
                if (signatureBytes.length > 0) {
                    let sigLabel = '└─ Signature:';
                    if (coseType.includes('Mac')) {
                        sigLabel = '└─ MAC:';
                    }
                    
                    components.push({
                        type: 'signature',
                        label: sigLabel,
                        bytes: signatureBytes
                    });
                }
            }
        } else {
            // Fallback: if no COSE structure detected, show all bytes as headers
            console.log('No COSE structure detected, showing all as headers');
            const headerBytes = [];
            bytes.forEach((byte, index) => {
                const mapEntry = this.currentByteMap.find(m => m.offset === index);
                headerBytes.push({
                    value: byte,
                    originalOffset: index,
                    mapEntry: mapEntry
                });
            });
            components.push({
                type: 'headers',
                label: null,
                bytes: headerBytes
            });
        }
        
        console.log('Final components:', components.length);
        components.forEach((comp, i) => {
            console.log(`  Component [${i}] ${comp.type}: ${comp.bytes.length} bytes, label: "${comp.label}"`);
        });
        
        return components;
    }
    
    /**
     * Extract COSE preamble bytes (CBOR tag + array structure, before first element)
     */
    extractCOSEPreamble(bytes) {
        const preambleBytes = [];
        const coseArrayElements = this.findCOSEArrayElements();
        
        if (coseArrayElements.length > 0) {
            const firstElementStart = coseArrayElements[0].startOffset;
            
            for (let i = 0; i < firstElementStart && i < bytes.length; i++) {
                const mapEntry = this.currentByteMap.find(m => m.offset === i);
                preambleBytes.push({
                    value: bytes[i],
                    originalOffset: i,
                    mapEntry: mapEntry
                });
            }
        }
        
        return preambleBytes;
    }
    
    /**
     * Extract protected headers bytes
     */
    extractProtectedHeaders(bytes, coseArrayElements) {
        const protectedBytes = [];
        
        if (coseArrayElements.length > 0) {
            const protectedElement = coseArrayElements[0]; // [0] Protected Headers
            
            for (let i = protectedElement.startOffset; i <= protectedElement.endOffset && i < bytes.length; i++) {
                const mapEntry = this.currentByteMap.find(m => m.offset === i);
                protectedBytes.push({
                    value: bytes[i],
                    originalOffset: i,
                    mapEntry: mapEntry
                });
            }
        }
        
        return protectedBytes;
    }
    
    /**
     * Extract unprotected headers bytes
     */
    extractUnprotectedHeaders(bytes, coseArrayElements) {
        const unprotectedBytes = [];
        
        if (coseArrayElements.length > 1) {
            const unprotectedElement = coseArrayElements[1]; // [1] Unprotected Headers
            
            for (let i = unprotectedElement.startOffset; i <= unprotectedElement.endOffset && i < bytes.length; i++) {
                const mapEntry = this.currentByteMap.find(m => m.offset === i);
                unprotectedBytes.push({
                    value: bytes[i],
                    originalOffset: i,
                    mapEntry: mapEntry
                });
            }
        }
        
        return unprotectedBytes;
    }
    
    /**
     * Extract payload bytes (encrypted or plain)
     */
    extractCOSEPayload(bytes) {
        const payloadBytes = [];
        const payloadRange = this.findPayloadRange();
        
        console.log('Payload range:', payloadRange);
        
        if (payloadRange) {
            // Check if we have an encrypted payload structure with raw bytes
            const encryptedStruct = this.currentStructures.find(s => 
                s.description && s.description.includes('Encrypted Payload') && s.raw
            );
            
            console.log('Found encrypted struct:', !!encryptedStruct);
            
            if (encryptedStruct && encryptedStruct.raw) {
                // Use the raw encrypted bytes
                console.log('Using raw encrypted bytes, count:', encryptedStruct.raw.length);
                encryptedStruct.raw.forEach((byte, index) => {
                    payloadBytes.push({
                        value: byte,
                        originalOffset: payloadRange.start + index,
                        mapEntry: { type: 'encrypted-payload', structureIndex: this.currentStructures.indexOf(encryptedStruct) }
                    });
                });
            } else {
                // Use regular bytes from the payload range
                console.log('Using regular bytes from range', payloadRange.start, 'to', payloadRange.end);
                for (let i = payloadRange.start; i <= payloadRange.end && i < bytes.length; i++) {
                    const mapEntry = this.currentByteMap.find(m => m.offset === i);
                    payloadBytes.push({
                        value: bytes[i],
                        originalOffset: i,
                        mapEntry: mapEntry
                    });
                }
            }
        }
        
        return payloadBytes;
    }
    
    /**
     * Extract decrypted payload bytes if available
     */
    extractDecryptedPayload() {
        const decryptedBytes = [];
        const decryptedStruct = this.currentStructures.find(s => s.isDecrypted && s.raw);
        
        if (decryptedStruct) {
            const decryptedByteMap = this.createDecryptedByteMap(decryptedStruct, 0);
            
            decryptedStruct.raw.forEach((byte, index) => {
                const mapEntry = decryptedByteMap.find(m => m.decryptedOffset === index);
                decryptedBytes.push({
                    value: byte,
                    originalOffset: index,
                    mapEntry: mapEntry,
                    isDecrypted: true
                });
            });
        }
        
        return decryptedBytes;
    }
    
    /**
     * Extract signature/MAC bytes if present
     */
    extractCOSESignature(bytes) {
        // Look for signature/MAC as the last element in COSE array
        const signatureBytes = [];
        const signatureRange = this.findSignatureRange();
        
        if (signatureRange) {
            for (let i = signatureRange.start; i <= signatureRange.end && i < bytes.length; i++) {
                const mapEntry = this.currentByteMap.find(m => m.offset === i);
                signatureBytes.push({
                    value: bytes[i],
                    originalOffset: i,
                    mapEntry: mapEntry
                });
            }
        }
        
        return signatureBytes;
    }
    
    // Helper methods
    findPayloadStartOffset() {
        const payloadRange = this.findPayloadRange();
        if (payloadRange) {
            return payloadRange.start;
        }
        
        // Fallback: look for structures that come after headers
        const coseArrayElements = this.findCOSEArrayElements();
        if (coseArrayElements.length > 2) {
            return coseArrayElements[2].startOffset; // Payload is 3rd element (index 2)
        }
        
        return this.currentByteMap.length;
    }
    
    findPayloadRange() {
        console.log('=== Finding Payload Range ===');
        
        // Fallback: look for the third item in COSE array structure first (more reliable)
        const coseArrayElements = this.findCOSEArrayElements();
        console.log('COSE array elements found:', coseArrayElements.length);
        
        if (coseArrayElements.length > 2) {
            const payload = coseArrayElements[2];
            console.log('Payload element:', payload.description, 'offset:', payload.startOffset, '-', payload.endOffset);
            return { start: payload.startOffset, end: payload.endOffset };
        }
        
        // Look for COSE array element [2] (payload) - fallback
        let payloadStruct = this.currentStructures.find(s => 
            s.description && s.description.includes('[2] Payload')
        );
        
        console.log('Found [2] Payload struct:', !!payloadStruct);
        
        // Also check for encrypted payload structures
        if (!payloadStruct) {
            payloadStruct = this.currentStructures.find(s => 
                s.description && s.description.includes('Encrypted Payload')
            );
            console.log('Found encrypted payload struct:', !!payloadStruct);
        }
        
        if (payloadStruct) {
            console.log('Using payload struct:', payloadStruct.description, 'offset:', payloadStruct.startOffset, '-', payloadStruct.endOffset);
            return { start: payloadStruct.startOffset, end: payloadStruct.endOffset };
        }
        
        console.log('No payload range found');
        return null;
    }
    
    findSignatureRange() {
        console.log('=== Finding Signature Range ===');
        
        // Fallback: look for the fourth item in COSE array structure first (more reliable)
        const coseArrayElements = this.findCOSEArrayElements();
        console.log('COSE array elements found:', coseArrayElements.length);
        
        if (coseArrayElements.length > 3) {
            const signature = coseArrayElements[3];
            console.log('Signature element:', signature.description, 'offset:', signature.startOffset, '-', signature.endOffset);
            return { start: signature.startOffset, end: signature.endOffset };
        }
        
        // Look for COSE array element [3] (signature) - fallback
        let sigStruct = this.currentStructures.find(s => 
            s.description && s.description.includes('[3] Signature')
        );
        
        console.log('Found [3] Signature struct:', !!sigStruct);
        
        // Also check for MAC structures
        if (!sigStruct) {
            sigStruct = this.currentStructures.find(s => 
                s.description && s.description.includes('MAC')
            );
            console.log('Found MAC struct:', !!sigStruct);
        }
        
        if (sigStruct) {
            console.log('Using signature struct:', sigStruct.description, 'offset:', sigStruct.startOffset, '-', sigStruct.endOffset);
            return { start: sigStruct.startOffset, end: sigStruct.endOffset };
        }
        
        console.log('No signature range found');
        return null;
    }
    
    /**
     * Find all direct children of the COSE array structure
     */
    findCOSEArrayElements() {
        const coseArrayIndex = this.currentStructures.findIndex(s => 
            s.description && s.description.includes('COSE Structure Array')
        );
        
        if (coseArrayIndex < 0) {
            console.log('No COSE Array found');
            return [];
        }
        
        const coseArray = this.currentStructures[coseArrayIndex];
        console.log(`COSE Array found at index ${coseArrayIndex}, indent: ${coseArray.indent}`);
        const elements = [];
        
        // Find structures that are direct children of the COSE array
        for (let i = coseArrayIndex + 1; i < this.currentStructures.length; i++) {
            const struct = this.currentStructures[i];
            console.log(`  Checking [${i}] indent:${struct.indent} desc:"${struct.description}"`);
            
            // Stop if we've moved past the COSE array's indent level
            if (struct.indent <= coseArray.indent) {
                console.log(`  Stopped at [${i}] - indent ${struct.indent} <= ${coseArray.indent}`);
                break;
            }
            
            // Look for array element indicators or actual data structures
            if (struct.indent === coseArray.indent + 1) {
                console.log(`  Found child at [${i}] - "${struct.description}"`);
                
                // Check if this is an element label like "[0] Protected Headers:"
                if (struct.description.match(/^\[\d+\]/)) {
                    console.log(`  This is an element label, looking for next structure...`);
                    const nextStruct = this.currentStructures[i + 1];
                    if (nextStruct && nextStruct.indent === coseArray.indent + 2) {
                        console.log(`  Found actual data structure: "${nextStruct.description}"`);
                        elements.push(nextStruct);
                        i++; // Skip the next structure since we've already processed it
                    }
                } else {
                    // This might be a direct data structure
                    console.log(`  Direct data structure: "${struct.description}"`);
                    elements.push(struct);
                }
            }
        }
        
        console.log(`Found ${elements.length} COSE array elements`);
        return elements;
    }
    
    isEncryptedPayload() {
        return this.currentStructures.some(s => 
            s.description && s.description.includes('Encrypted Payload')
        );
    }
    
    /**
     * Determine the COSE type from the CBOR tag(s)
     */
    determineCOSEType() {
        // Look for any COSE-related tag in the structure
        const coseTagStruct = this.currentStructures.find(s => 
            s.majorType === 6 && s.description && (
                s.description.includes('COSE_Encrypt0') ||
                s.description.includes('COSE_Encrypt') ||
                s.description.includes('COSE_Sign1') ||
                s.description.includes('COSE_Sign') ||
                s.description.includes('COSE_Mac0') ||
                s.description.includes('COSE_Mac')
            )
        );
        
        if (coseTagStruct) {
            const description = coseTagStruct.description;
            if (description.includes('COSE_Encrypt0')) return 'COSE_Encrypt0';
            if (description.includes('COSE_Encrypt')) return 'COSE_Encrypt';  
            if (description.includes('COSE_Sign1')) return 'COSE_Sign1';
            if (description.includes('COSE_Sign')) return 'COSE_Sign';
            if (description.includes('COSE_Mac0')) return 'COSE_Mac0';
            if (description.includes('COSE_Mac')) return 'COSE_Mac';
        }
        
        // Fallback: check if we have a COSE Structure Array (might be nested in CWT)
        const coseArrayStruct = this.currentStructures.find(s => 
            s.description && s.description.includes('COSE Structure Array')
        );
        
        if (coseArrayStruct) {
            // Try to infer type from array length and context
            const arrayMatch = coseArrayStruct.description.match(/\((\d+) items\)/);
            if (arrayMatch) {
                const itemCount = parseInt(arrayMatch[1]);
                if (itemCount === 4) {
                    // Could be Sign1 or Sign - look for signature-like structures
                    const hasSignature = this.currentStructures.some(s => 
                        s.description && (s.description.includes('Signature') || s.description.includes('[3]'))
                    );
                    return hasSignature ? 'COSE_Sign1' : 'COSE_Sign';
                } else if (itemCount === 3) {
                    // Could be Encrypt0, Mac0 - look for encrypted payload
                    const hasEncrypted = this.currentStructures.some(s => 
                        s.description && s.description.includes('Encrypted Payload')
                    );
                    return hasEncrypted ? 'COSE_Encrypt0' : 'COSE_Mac0';
                }
            }
        }
        
        return 'Unknown';
    }
    
    /**
     * Create byte element for a specific component
     */
    createByteElementForComponent(byteInfo, component, byteIndex, onHighlight, onClearHighlight) {
        const byteElement = document.createElement('span');
        byteElement.className = 'cbor-byte';
        byteElement.textContent = byteInfo.value.toString(16).padStart(2, '0').toUpperCase();
        
        // Add component-specific styling
        if (component.type === 'payload' && this.isEncryptedPayload()) {
            byteElement.classList.add('cbor-byte-encrypted-payload');
        } else if (component.type === 'decrypted') {
            byteElement.classList.add('cbor-byte-decrypted-content');
        }
        
        // Set appropriate data attributes
        if (byteInfo.isDecrypted) {
            byteElement.dataset.decryptedIndex = byteIndex;
        } else {
            byteElement.dataset.offset = byteInfo.originalOffset;
        }
        
        // Add type-specific classes
        if (byteInfo.mapEntry) {
            byteElement.dataset.structureIndex = byteInfo.mapEntry.structureIndex;
            
            if (byteInfo.mapEntry.type === 'major') {
                byteElement.classList.add('cbor-byte-major');
            } else if (byteInfo.mapEntry.type === 'length') {
                byteElement.classList.add('cbor-byte-length');
            } else if (byteInfo.mapEntry.type === 'value') {
                byteElement.classList.add('cbor-byte-value');
            }
        }
        
        // Add event listeners
        byteElement.addEventListener('mouseenter', () => {
            if (byteInfo.mapEntry && byteInfo.mapEntry.structureIndex !== undefined) {
                this.highlightRelatedHover(byteInfo.mapEntry.structureIndex, 'structure', onHighlight);
            }
        });
        byteElement.addEventListener('mouseleave', () => {
            this.clearHighlight(onClearHighlight);
        });
        byteElement.addEventListener('click', () => {
            if (byteInfo.mapEntry && byteInfo.mapEntry.structureIndex !== undefined) {
                this.highlightRelated(byteInfo.mapEntry.structureIndex, 'structure', onHighlight);
            }
        });
        
        return byteElement;
    }
    
    /**
     * Create a standard byte element
     */
    createByteElement(byte, index, mapEntry, onHighlight, onClearHighlight) {
        const byteElement = document.createElement('span');
        byteElement.className = 'cbor-byte';
        byteElement.textContent = byte.toString(16).padStart(2, '0').toUpperCase();
        byteElement.dataset.offset = index;
        
        if (mapEntry) {
            byteElement.dataset.structureIndex = mapEntry.structureIndex;
            
            // Add color coding based on type
            if (mapEntry.type === 'major') {
                byteElement.classList.add('cbor-byte-major');
            } else if (mapEntry.type === 'length') {
                byteElement.classList.add('cbor-byte-length');
            } else if (mapEntry.type === 'value') {
                byteElement.classList.add('cbor-byte-value');
            }
        }
        
        byteElement.addEventListener('mouseenter', () => {
            this.highlightRelatedHover(index, 'byte', onHighlight);
        });
        byteElement.addEventListener('mouseleave', () => {
            this.clearHighlight(onClearHighlight);
        });
        byteElement.addEventListener('click', () => {
            this.highlightRelated(index, 'byte', onHighlight);
        });
        
        return byteElement;
    }
    
    /**
     * Create a decrypted byte element
     */
    createDecryptedByteElement(byte, index, mapEntry, onHighlight, onClearHighlight) {
        const byteElement = document.createElement('span');
        byteElement.className = 'cbor-byte cbor-byte-decrypted-content';
        byteElement.textContent = byte.toString(16).padStart(2, '0').toUpperCase();
        byteElement.dataset.decryptedIndex = index;
        
        if (mapEntry) {
            byteElement.dataset.structureIndex = mapEntry.structureIndex;
            
            // Add type classes for decrypted bytes
            if (mapEntry.type === 'major') {
                byteElement.classList.add('cbor-byte-major');
            } else if (mapEntry.type === 'length') {
                byteElement.classList.add('cbor-byte-length');
            } else if (mapEntry.type === 'value') {
                byteElement.classList.add('cbor-byte-value');
            }
            
            byteElement.addEventListener('mouseenter', () => {
                this.highlightRelatedHover(mapEntry.structureIndex, 'structure', onHighlight);
            });
            byteElement.addEventListener('click', () => {
                this.highlightRelated(mapEntry.structureIndex, 'structure', onHighlight);
            });
        }
        
        byteElement.addEventListener('mouseleave', () => {
            this.clearHighlight(onClearHighlight);
        });
        
        return byteElement;
    }
    
    
    /**
     * Create a byte map for decrypted content linking to embedded structures
     */
    createDecryptedByteMap(decryptedStructure, structIndex) {
        const byteMap = [];
        const embeddedStructures = this.currentStructures.filter(s => s.isEmbeddedInDecrypted);
        
        // Get the embedded byte map from the decrypted structure itself
        let embeddedByteMap = [];
        if (decryptedStructure.embeddedByteMap) {
            embeddedByteMap = decryptedStructure.embeddedByteMap;
        }
        
        // Create the decrypted byte map using the stored embedded byte map
        embeddedByteMap.forEach(mapEntry => {
            // Make sure we're mapping to the correct structure index
            // The mapEntry.structureIndex should already point to the embedded structures
            // but let's verify it's actually an embedded structure
            const targetStruct = this.currentStructures[mapEntry.structureIndex];
            if (targetStruct && targetStruct.isEmbeddedInDecrypted) {
                byteMap.push({
                    decryptedOffset: mapEntry.offset,
                    structureIndex: mapEntry.structureIndex,
                    type: mapEntry.type
                });
            }
        });
        
        // If we don't have enough mappings, create a simple sequential mapping
        if (byteMap.length === 0 && embeddedStructures.length > 0) {
            for (let i = 0; i < decryptedStructure.raw.length; i++) {
                // Find which structure this byte belongs to based on offsets
                let targetStructIndex = this.currentStructures.indexOf(embeddedStructures[0]);
                
                for (const struct of embeddedStructures) {
                    if (struct.startOffset !== undefined && struct.endOffset !== undefined &&
                        i >= struct.startOffset && i <= struct.endOffset) {
                        targetStructIndex = this.currentStructures.indexOf(struct);
                        break;
                    }
                }
                
                byteMap.push({
                    decryptedOffset: i,
                    structureIndex: targetStructIndex,
                    type: 'value'
                });
            }
        }
        
        return byteMap;
    }

    /**
     * Display CBOR structure with interactive highlighting
     */
    displayStructure(structures, container, onHighlight, onClearHighlight) {
        container.innerHTML = '';
        
        structures.forEach((structure, index) => {
            const item = document.createElement('div');
            item.className = `cbor-structure-item cbor-indent-${Math.min(structure.indent, 4)}`;
            item.dataset.structureIndex = index;
            item.dataset.startOffset = structure.startOffset;
            item.dataset.endOffset = structure.endOffset;
            
            let content = structure.description;
            
            // Add type tags
            if (structure.majorType !== undefined) {
                const majorTypeNames = [
                    'Unsigned', 'Negative', 'ByteString', 'TextString', 
                    'Array', 'Map', 'Tag', 'Float/Simple'
                ];
                content = `<span class="cbor-type-tag cbor-type-major">${majorTypeNames[structure.majorType]}</span> ${content}`;
            }
            
            item.innerHTML = content;
            
            item.addEventListener('mouseenter', () => {
                this.highlightRelatedHover(index, 'structure', onHighlight);
            });
            item.addEventListener('mouseleave', () => {
                this.clearHighlight(onClearHighlight);
            });
            item.addEventListener('click', () => {
                this.highlightRelated(index, 'structure', onHighlight);
            });
            
            container.appendChild(item);
        });
    }

    /**
     * Highlight related bytes and structure elements (hover only - no scrolling)
     */
    highlightRelatedHover(value, source, onHighlight) {
        this.clearHighlight();
        
        if (source === 'byte') {
            // Highlight byte
            const byteElement = document.querySelector(`.cbor-byte[data-offset="${value}"]`);
            if (byteElement) {
                byteElement.classList.add('cbor-highlighted');
                
                // Find and highlight related structure
                const structureIndex = byteElement.dataset.structureIndex;
                if (structureIndex !== undefined) {
                    const structureElement = document.querySelector(`.cbor-structure-item[data-structure-index="${structureIndex}"]`);
                    if (structureElement) {
                        structureElement.classList.add('cbor-highlighted');
                    }
                }
            }
        } else if (source === 'structure') {
            // Highlight structure
            const structureElement = document.querySelector(`.cbor-structure-item[data-structure-index="${value}"]`);
            if (structureElement) {
                structureElement.classList.add('cbor-highlighted');
                
                // Check if this is an embedded structure
                const structure = this.currentStructures[value];
                if (structure && structure.isEmbeddedInDecrypted) {
                    // Highlight decrypted bytes instead of main CBOR bytes
                    this.highlightDecryptedBytes(structure, value);
                } else {
                    // Highlight regular CBOR bytes
                    const startOffset = parseInt(structureElement.dataset.startOffset);
                    const endOffset = parseInt(structureElement.dataset.endOffset);
                    
                    if (!isNaN(startOffset) && !isNaN(endOffset)) {
                        for (let i = startOffset; i <= endOffset; i++) {
                            const byteElement = document.querySelector(`.cbor-byte[data-offset="${i}"]`);
                            if (byteElement) {
                                byteElement.classList.add('cbor-highlighted');
                            }
                        }
                    }
                }
            }
        }
        
        if (onHighlight) {
            onHighlight(value, source);
        }
    }
    
    /**
     * Highlight decrypted bytes for embedded structures
     */
    highlightDecryptedBytes(structure, structureIndex) {
        // Find the decrypted structure that contains this embedded structure
        const decryptedParent = this.currentStructures[structure.decryptedParentIndex];
        if (!decryptedParent || !decryptedParent.embeddedByteMap) {
            return;
        }
        
        // Find which decrypted bytes correspond to this structure
        const relatedBytes = decryptedParent.embeddedByteMap.filter(mapEntry => 
            mapEntry.structureIndex === structureIndex
        );
        
        // Highlight those bytes in the decrypted section
        relatedBytes.forEach(mapEntry => {
            const decryptedByte = document.querySelector(`[data-decrypted-index="${mapEntry.offset}"]`);
            if (decryptedByte) {
                decryptedByte.classList.add('cbor-highlighted');
            }
        });
    }

    /**
     * Highlight related bytes and structure elements (click - with scrolling)
     */
    highlightRelated(value, source, onHighlight) {
        this.clearHighlight();
        
        if (source === 'byte') {
            // Highlight byte
            const byteElement = document.querySelector(`.cbor-byte[data-offset="${value}"]`);
            if (byteElement) {
                byteElement.classList.add('cbor-highlighted');
                
                // Find and highlight related structure
                const structureIndex = byteElement.dataset.structureIndex;
                if (structureIndex !== undefined) {
                    const structureElement = document.querySelector(`.cbor-structure-item[data-structure-index="${structureIndex}"]`);
                    if (structureElement) {
                        structureElement.classList.add('cbor-highlighted');
                        // Scroll structure element into view
                        this.scrollIntoViewIfNeeded(structureElement);
                    }
                }
            }
        } else if (source === 'structure') {
            // Highlight structure
            const structureElement = document.querySelector(`.cbor-structure-item[data-structure-index="${value}"]`);
            if (structureElement) {
                structureElement.classList.add('cbor-highlighted');
                
                // Check if this is an embedded structure
                const structure = this.currentStructures[value];
                if (structure && structure.isEmbeddedInDecrypted) {
                    // Highlight decrypted bytes instead of main CBOR bytes
                    this.highlightDecryptedBytes(structure, value);
                } else {
                    // Highlight regular CBOR bytes and scroll first byte into view
                    const startOffset = parseInt(structureElement.dataset.startOffset);
                    const endOffset = parseInt(structureElement.dataset.endOffset);
                    
                    if (!isNaN(startOffset) && !isNaN(endOffset)) {
                        let firstByteElement = null;
                        for (let i = startOffset; i <= endOffset; i++) {
                            const byteElement = document.querySelector(`.cbor-byte[data-offset="${i}"]`);
                            if (byteElement) {
                                byteElement.classList.add('cbor-highlighted');
                                if (!firstByteElement) {
                                    firstByteElement = byteElement;
                                }
                            }
                        }
                        // Scroll first byte into view
                        if (firstByteElement) {
                            this.scrollIntoViewIfNeeded(firstByteElement);
                        }
                    }
                }
            }
        }
        
        if (onHighlight) {
            onHighlight(value, source);
        }
    }

    /**
     * Scroll element into view if it's not currently visible
     */
    scrollIntoViewIfNeeded(element) {
        const container = element.closest('.cbor-bytes-container, .cbor-structure-container');
        if (!container) return;

        const containerRect = container.getBoundingClientRect();
        const elementRect = element.getBoundingClientRect();
        
        // Check if element is outside the container's visible area
        const isAbove = elementRect.top < containerRect.top;
        const isBelow = elementRect.bottom > containerRect.bottom;
        const isLeft = elementRect.left < containerRect.left;
        const isRight = elementRect.right > containerRect.right;
        
        if (isAbove || isBelow || isLeft || isRight) {
            // Calculate scroll position to center the element
            const containerCenterY = containerRect.height / 2;
            const containerCenterX = containerRect.width / 2;
            const elementCenterY = elementRect.height / 2;
            const elementCenterX = elementRect.width / 2;
            
            const scrollTop = container.scrollTop + (elementRect.top - containerRect.top) - containerCenterY + elementCenterY;
            const scrollLeft = container.scrollLeft + (elementRect.left - containerRect.left) - containerCenterX + elementCenterX;
            
            container.scrollTo({
                top: Math.max(0, scrollTop),
                left: Math.max(0, scrollLeft),
                behavior: 'smooth'
            });
        }
    }

    /**
     * Clear all highlighting
     */
    clearHighlight(onClearHighlight) {
        document.querySelectorAll('.cbor-highlighted').forEach(el => {
            el.classList.remove('cbor-highlighted');
        });
        
        if (onClearHighlight) {
            onClearHighlight();
        }
    }

    /**
     * Get default CSS styles for the visualizer
     */
    static getDefaultStyles() {
        return `
            .cbor-byte {
                padding: 4px 6px;
                background: #f0f0f0;
                border-radius: 4px;
                cursor: pointer;
                transition: all 0.2s;
                font-size: 14px;
                font-family: 'Courier New', monospace;
                display: inline-block;
                margin: 2px;
                border: 2px solid transparent;
            }

            .cbor-byte:hover {
                background: #e0e0e0;
                transform: scale(1.1);
            }

            .cbor-byte.cbor-highlighted {
                background: #ffd700;
                border-color: #ffa500;
                font-weight: bold;
            }

            .cbor-byte-major { background: #e3f2fd; }
            .cbor-byte-length { background: #f3e5f5; }
            .cbor-byte-value { background: #e8f5e9; }
            
            .cbor-byte-encrypted-payload {
                border-bottom: 2px solid #ff9800;
            }
            
            .cbor-byte-decrypted-content {
                background: #e8f5e8;
            }

            .cbor-bytes-tree-level {
                display: block;
                width: 100%;
                margin: 6px 0;
                line-height: 1.4;
                padding: 4px 0;
                clear: both;
            }

            .cbor-bytes-protected-headers-level,
            .cbor-bytes-unprotected-headers-level,
            .cbor-bytes-payload-level,
            .cbor-bytes-signature-level {
                display: block;
                width: 100%;
                margin-left: 20px;
                margin: 8px 0;
                padding: 6px 0;
                clear: both;
            }

            .cbor-bytes-encrypted-level {
                margin-left: 20px;
                margin: 8px 0;
                padding: 6px 0;
            }

            .cbor-bytes-decrypted-level {
                margin-left: 20px;
                margin: 8px 0;
                padding: 6px 0;
            }

            .cbor-bytes-tree-label {
                font-family: 'Courier New', monospace;
                font-size: 12px;
                color: #888;
                margin: 6px 0 2px 0;
                user-select: none;
                font-weight: normal;
            }

            .cbor-component-separator {
                display: block;
                width: 100%;
                height: 12px;
                margin: 8px 0;
                border-bottom: 1px solid #ddd;
                clear: both;
            }

            .cbor-structure-item {
                font-family: 'Courier New', monospace;
                font-size: 14px;
                line-height: 1.6;
                padding: 4px 8px;
                border-radius: 4px;
                margin: 2px 0;
                cursor: pointer;
                transition: background 0.2s;
                position: relative;
            }

            .cbor-structure-item:hover {
                background: #f0f0f0;
            }

            .cbor-structure-item.cbor-highlighted {
                background: #ffd700;
            }

            .cbor-indent-0 { padding-left: 8px; }
            .cbor-indent-1 { padding-left: 30px; }
            .cbor-indent-2 { padding-left: 60px; }
            .cbor-indent-3 { padding-left: 90px; }
            .cbor-indent-4 { padding-left: 120px; }

            .cbor-type-tag {
                display: inline-block;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 11px;
                margin-left: 8px;
                font-weight: bold;
                text-transform: uppercase;
            }

            .cbor-type-major { background: #e3f2fd; color: #1976d2; }
            .cbor-type-length { background: #f3e5f5; color: #7b1fa2; }
            .cbor-type-value { background: #e8f5e9; color: #388e3c; }
            .cbor-type-tag-cbor { background: #fff3e0; color: #f57c00; }
        `;
    }
}

/**
 * CBOR Decoder class for visualization (renamed to avoid conflicts)
 */
class CBORVisualizationDecoder {
    constructor(bytes, options = {}) {
        this.bytes = bytes;
        this.offset = 0;
        this.structures = [];
        this.byteMap = [];
        this.decryptedPayloads = options.decryptedPayloads || [];
    }
    
    findDecryptedPayload(originalBytes) {
        // Find matching decrypted payload for the given encrypted bytes
        for (const payload of this.decryptedPayloads) {
            if (this.arraysEqual(payload.originalBytes, originalBytes)) {
                return payload.decryptedBytes;
            }
        }
        return null;
    }
    
    arraysEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    decode() {
        this.structures = [];
        this.byteMap = [];
        this.offset = 0;
        
        try {
            this.decodeItem(0);
            return { structures: this.structures, byteMap: this.byteMap };
        } catch (e) {
            throw new Error(`CBOR decode error at byte ${this.offset}: ${e.message}`);
        }
    }

    decodeItem(indent = 0, context = null) {
        if (this.offset >= this.bytes.length) {
            throw new Error('Unexpected end of input');
        }

        const startOffset = this.offset;
        const initialByte = this.bytes[this.offset];
        const majorType = (initialByte & 0xe0) >> 5;
        const additionalInfo = initialByte & 0x1f;

        this.byteMap.push({ offset: this.offset, type: 'major', structureIndex: this.structures.length });
        this.offset++;

        let value;
        let lengthBytes = 0;

        // Decode length/value based on additional info
        if (additionalInfo < 24) {
            value = additionalInfo;
        } else if (additionalInfo === 24) {
            lengthBytes = 1;
            value = this.bytes[this.offset];
            this.byteMap.push({ offset: this.offset, type: 'length', structureIndex: this.structures.length });
            this.offset++;
        } else if (additionalInfo === 25) {
            lengthBytes = 2;
            value = (this.bytes[this.offset] << 8) | this.bytes[this.offset + 1];
            for (let i = 0; i < 2; i++) {
                this.byteMap.push({ offset: this.offset + i, type: 'length', structureIndex: this.structures.length });
            }
            this.offset += 2;
        } else if (additionalInfo === 26) {
            lengthBytes = 4;
            value = (this.bytes[this.offset] << 24) | (this.bytes[this.offset + 1] << 16) |
                    (this.bytes[this.offset + 2] << 8) | this.bytes[this.offset + 3];
            for (let i = 0; i < 4; i++) {
                this.byteMap.push({ offset: this.offset + i, type: 'length', structureIndex: this.structures.length });
            }
            this.offset += 4;
        } else if (additionalInfo === 27) {
            lengthBytes = 8;
            // For simplicity, treating as regular number (may lose precision for very large numbers)
            value = 0;
            for (let i = 0; i < 8; i++) {
                value = value * 256 + this.bytes[this.offset + i];
                this.byteMap.push({ offset: this.offset + i, type: 'length', structureIndex: this.structures.length });
            }
            this.offset += 8;
        }

        const structure = {
            indent,
            startOffset,
            endOffset: null,
            majorType,
            additionalInfo,
            value,
            description: '',
            raw: []
        };

        // Process based on major type
        switch (majorType) {
            case 0: // Unsigned integer
                structure.description = `Unsigned Integer: ${value}`;
                
                // Check if this is a CWT claim key or COSE header key
                if (context === 'cwt-key' || context === 'cose-header-key') {
                    const claimName = this.getCWTClaimName(value);
                    if (claimName) {
                        structure.description += ` [${claimName}]`;
                    }
                }
                
                // Check if this is a COSE algorithm identifier (alg parameter = 1)
                if (context === 'cose-header-value' && value >= 0) {
                    const algorithmName = this.getCOSEAlgorithmName(value);
                    if (algorithmName && algorithmName !== `Algorithm ${value}`) {
                        structure.description = `Algorithm: ${algorithmName} (${value})`;
                    }
                }
                
                structure.endOffset = this.offset - 1;
                break;

            case 1: // Negative integer
                const negValue = -1 - value;
                structure.description = `Negative Integer: ${negValue}`;
                
                // Check for COSE header parameters (negative integers)
                if (context === 'cose-header-key') {
                    const headerParam = this.getCOSEHeaderParam(negValue);
                    if (headerParam) {
                        structure.description += ` [${headerParam}]`;
                    }
                }
                
                // Check if this is a COSE algorithm identifier (negative algorithms like ES256 = -7)
                if (context === 'cose-header-value') {
                    const algorithmName = this.getCOSEAlgorithmName(negValue);
                    if (algorithmName && algorithmName !== `Algorithm ${negValue}`) {
                        structure.description = `Algorithm: ${algorithmName} (${negValue})`;
                    }
                }
                
                structure.endOffset = this.offset - 1;
                break;

            case 2: // Byte string
                structure.description = `Byte String (${value} bytes)`;
                this.structures.push(structure);
                
                const byteStringStart = this.offset;
                const byteString = this.bytes.slice(this.offset, this.offset + value);
                
                // Try to decode as CBOR if in COSE context
                if (context === 'cose-protected' || context === 'cose-payload') {
                    try {
                        // Check if this is an encrypted payload that we have decrypted
                        const decryptedPayload = this.findDecryptedPayload(byteString);
                        
                        if (decryptedPayload) {
                            const encryptedStructureIndex = this.structures.length;
                            
                            // Show encrypted payload
                            this.structures.push({
                                indent: indent + 1,
                                startOffset: byteStringStart,
                                endOffset: byteStringStart + value - 1,
                                description: `[Encrypted Payload - ${value} bytes]`,
                                raw: Array.from(byteString),
                                isEncrypted: true
                            });
                            
                            // Show decrypted content header
                            this.structures.push({
                                indent: indent + 1,
                                startOffset: byteStringStart,
                                endOffset: byteStringStart + value - 1,
                                description: `[Decrypted Content - ${decryptedPayload.length} bytes]`,
                                raw: Array.from(decryptedPayload),
                                isDecrypted: true,
                                encryptedStructureIndex: encryptedStructureIndex
                            });
                            
                            // Decode the decrypted CBOR - these structures will be linked to decrypted bytes
                            const embeddedStartIndex = this.structures.length;
                            const embeddedByteMap = this.decodeEmbeddedCBOR(decryptedPayload, indent + 2, 'cwt', 0); // Use 0 as base offset for decrypted content
                            
                            // Mark embedded structures as belonging to decrypted content
                            for (let i = embeddedStartIndex; i < this.structures.length; i++) {
                                this.structures[i].isEmbeddedInDecrypted = true;
                                this.structures[i].decryptedParentIndex = embeddedStartIndex - 1;
                            }
                            
                            // Store the embedded byte map on the decrypted structure
                            const decryptedStructIndex = embeddedStartIndex - 1;
                            if (this.structures[decryptedStructIndex]) {
                                this.structures[decryptedStructIndex].embeddedByteMap = embeddedByteMap;
                            }
                        } else {
                            // Normal CBOR decoding for non-encrypted payloads
                            // First, try to parse as CBOR to see if it's valid
                            const innerDecoder = new CBORVisualizationDecoder(Array.from(byteString));
                            const embedContext = context === 'cose-payload' ? 'cwt' : 'cose-header';
                            
                            // Add header for embedded CBOR
                            this.structures.push({
                                indent: indent + 1,
                                startOffset: byteStringStart,
                                endOffset: byteStringStart + value - 1,
                                description: `[Embedded CBOR]`,
                                raw: Array.from(byteString)
                            });
                            
                            // Decode embedded CBOR with offset tracking
                            this.decodeEmbeddedCBOR(byteString, indent + 2, embedContext, byteStringStart);
                        }
                        
                        // Mark all bytes as part of the embedded structure
                        for (let i = 0; i < value; i++) {
                            this.byteMap.push({ 
                                offset: this.offset + i, 
                                type: 'value', 
                                structureIndex: this.structures.length - 1 
                            });
                        }
                        
                        this.offset += value;
                    } catch (e) {
                        // Not CBOR, show as hex
                        for (let i = 0; i < value; i++) {
                            this.byteMap.push({ offset: this.offset + i, type: 'value', structureIndex: this.structures.length - 1 });
                        }
                        
                        this.structures.push({
                            indent: indent + 1,
                            startOffset: byteStringStart,
                            endOffset: byteStringStart + value - 1,
                            description: `Bytes: ${Array.from(byteString).map(b => b.toString(16).padStart(2, '0')).join(' ')}`,
                            raw: Array.from(byteString)
                        });
                        
                        this.offset += value;
                    }
                } else {
                    // Regular byte string
                    for (let i = 0; i < value; i++) {
                        this.byteMap.push({ offset: this.offset + i, type: 'value', structureIndex: this.structures.length - 1 });
                    }
                    
                    this.structures.push({
                        indent: indent + 1,
                        startOffset: byteStringStart,
                        endOffset: byteStringStart + value - 1,
                        description: `Bytes: ${Array.from(byteString).map(b => b.toString(16).padStart(2, '0')).join(' ')}`,
                        raw: Array.from(byteString)
                    });
                    
                    this.offset += value;
                }
                
                structure.endOffset = this.offset - 1;
                return;

            case 3: // Text string
                structure.description = `Text String (${value} bytes)`;
                this.structures.push(structure);
                
                const textStart = this.offset;
                for (let i = 0; i < value; i++) {
                    this.byteMap.push({ offset: this.offset + i, type: 'value', structureIndex: this.structures.length - 1 });
                }
                
                const textBytes = this.bytes.slice(this.offset, this.offset + value);
                const text = new TextDecoder().decode(new Uint8Array(textBytes));
                this.offset += value;
                
                this.structures.push({
                    indent: indent + 1,
                    startOffset: textStart,
                    endOffset: this.offset - 1,
                    description: `Text: "${text}"`,
                    raw: Array.from(textBytes)
                });
                
                structure.endOffset = this.offset - 1;
                return;

            case 4: // Array
                structure.description = `Array (${value} items)`;
                
                // Check if this is a COSE structure
                if (context === 'cose') {
                    structure.description = `COSE Structure Array (${value} items)`;
                }
                
                this.structures.push(structure);
                
                for (let i = 0; i < value; i++) {
                    let itemContext = null;
                    let itemDesc = `[${i}]:`;
                    
                    // COSE structure elements
                    if (context === 'cose') {
                        if (i === 0) {
                            itemDesc = `[0] Protected Headers:`;
                            itemContext = 'cose-protected';
                        } else if (i === 1) {
                            itemDesc = `[1] Unprotected Headers:`;
                            itemContext = 'cose-header';
                        } else if (i === 2) {
                            itemDesc = `[2] Payload:`;
                            itemContext = 'cose-payload';
                        } else if (i === 3) {
                            itemDesc = `[3] Signature:`;
                            itemContext = 'cose-signature';
                        }
                    }
                    
                    this.structures.push({
                        indent: indent + 1,
                        startOffset: this.offset,
                        endOffset: null,
                        description: itemDesc
                    });
                    this.decodeItem(indent + 2, itemContext);
                }
                
                structure.endOffset = this.offset - 1;
                return;

            case 5: // Map
                structure.description = `Map (${value} pairs)`;
                
                // Check context for CWT or COSE headers
                if (context === 'cwt') {
                    structure.description = `CWT Claims Map (${value} pairs)`;
                } else if (context === 'cose-header') {
                    structure.description = `COSE Header Map (${value} pairs)`;
                }
                
                this.structures.push(structure);
                
                for (let i = 0; i < value; i++) {
                    // Determine key context
                    let keyContext = null;
                    if (context === 'cwt') {
                        keyContext = 'cwt-key';
                    } else if (context === 'cose-header') {
                        keyContext = 'cose-header-key';
                    }
                    
                    this.structures.push({
                        indent: indent + 1,
                        startOffset: this.offset,
                        endOffset: null,
                        description: `Key ${i}:`
                    });
                    
                    // Save key value to determine value context
                    const keyStartOffset = this.offset;
                    const keyInitialByte = this.bytes[this.offset];
                    const keyMajorType = (keyInitialByte & 0xe0) >> 5;
                    const keyAdditionalInfo = keyInitialByte & 0x1f;
                    
                    let keyValue = null;
                    if (keyMajorType === 0 && keyAdditionalInfo < 24) {
                        keyValue = keyAdditionalInfo; // Simple positive integer key
                    } else if (keyMajorType === 1 && keyAdditionalInfo < 24) {
                        keyValue = -1 - keyAdditionalInfo; // Simple negative integer key
                    }
                    
                    this.decodeItem(indent + 2, keyContext);
                    
                    // Determine value context based on key
                    let valueContext = null;
                    if (context === 'cose-header' && keyValue === 1) {
                        valueContext = 'cose-header-value'; // Algorithm parameter
                    }
                    
                    this.structures.push({
                        indent: indent + 1,
                        startOffset: this.offset,
                        endOffset: null,
                        description: `Value ${i}:`
                    });
                    this.decodeItem(indent + 2, valueContext);
                }
                
                structure.endOffset = this.offset - 1;
                return;

            case 6: // Semantic tag
                structure.description = `CBOR Tag: ${value}`;
                
                // Special handling for known tags
                let tagContext = null;
                if (value === 98) {
                    structure.description += ` (COSE_Sign1)`;
                    tagContext = 'cose';
                } else if (value === 96) {
                    structure.description += ` (COSE_Encrypt0)`;
                    tagContext = 'cose';
                } else if (value === 16) {
                    structure.description += ` (COSE_Encrypt)`;
                    tagContext = 'cose';
                } else if (value === 17) {
                    structure.description += ` (COSE_Mac0)`;
                    tagContext = 'cose';
                } else if (value === 18) {
                    structure.description += ` (COSE_Sign1)`;
                    tagContext = 'cose';
                } else if (value === 61) {
                    structure.description += ` (CWT)`;
                    tagContext = 'cwt';
                }
                
                this.structures.push(structure);
                this.decodeItem(indent + 1, tagContext);
                structure.endOffset = this.offset - 1;
                return;

            case 7: // Floating point, simple values, break
                if (additionalInfo === 20) {
                    structure.description = 'False';
                } else if (additionalInfo === 21) {
                    structure.description = 'True';
                } else if (additionalInfo === 22) {
                    structure.description = 'Null';
                } else if (additionalInfo === 23) {
                    structure.description = 'Undefined';
                } else if (additionalInfo === 25) {
                    // Half-precision float
                    structure.description = `Float16: ${value}`;
                } else if (additionalInfo === 26) {
                    // Single-precision float
                    structure.description = `Float32: ${value}`;
                } else if (additionalInfo === 27) {
                    // Double-precision float
                    structure.description = `Float64: ${value}`;
                } else {
                    structure.description = `Simple Value: ${value}`;
                }
                structure.endOffset = this.offset - 1;
                break;

            default:
                structure.description = `Unknown Major Type: ${majorType}`;
                structure.endOffset = this.offset - 1;
        }

        this.structures.push(structure);
    }
    
    getCWTClaimName(key) {
        const claims = {
            1: 'iss (Issuer)',
            2: 'sub (Subject)',
            3: 'aud (Audience)',
            4: 'exp (Expiration Time)',
            5: 'nbf (Not Before)',
            6: 'iat (Issued At)',
            7: 'cti (CWT ID)',
            8: 'cnf (Confirmation)',
            9: 'scope',
            // ACE-OAuth claims
            38: 'cnonce',
            39: 'exi',
            // Common private claims
            65: 'nonce'
        };
        return claims[key] || null;
    }
    
    getCOSEHeaderParam(key) {
        const params = {
            1: 'alg (Algorithm)',
            2: 'crit (Critical)',
            3: 'content type',
            4: 'kid (Key ID)',
            5: 'IV',
            6: 'Partial IV',
            7: 'counter signature'
        };
        return params[Math.abs(key)] || null;
    }
    
    getCOSEAlgorithmName(algId) {
        const algorithms = {
            '-7': 'ES256 (ECDSA w/ SHA-256)',
            '-35': 'ES384 (ECDSA w/ SHA-384)', 
            '-36': 'ES512 (ECDSA w/ SHA-512)',
            '1': 'AES-GCM-128',
            '4': 'HMAC 256/64',
            '5': 'HMAC 256/256',
            '6': 'HMAC 384/384',
            '7': 'HMAC 512/512',
            '10': 'AES-CCM-16-64-128'
        };
        return algorithms[String(algId)] || `Algorithm ${algId}`;
    }
    
    decodeEmbeddedCBOR(embeddedBytes, indent, context, baseOffset) {
        // Save current state
        const savedOffset = this.offset;
        const savedBytes = this.bytes;
        
        // Create a temporary decoder for the embedded CBOR
        const tempDecoder = new CBORVisualizationDecoder(Array.from(embeddedBytes));
        tempDecoder.byteMap = [];
        tempDecoder.structures = [];
        
        // Decode the embedded structure
        tempDecoder.decodeItem(0, context);
        
        // Store the current structures length to calculate new indices
        const structuresLengthBefore = this.structures.length;
        
        // Now add the decoded structures with adjusted offsets and indentation
        for (const struct of tempDecoder.structures) {
            this.structures.push({
                ...struct,
                indent: struct.indent + indent,
                startOffset: struct.startOffset + baseOffset,
                endOffset: struct.endOffset !== null ? struct.endOffset + baseOffset : null
            });
        }
        
        // Add byte mappings with adjusted offsets
        for (const mapping of tempDecoder.byteMap) {
            this.byteMap.push({
                ...mapping,
                offset: mapping.offset + baseOffset,
                structureIndex: mapping.structureIndex + structuresLengthBefore
            });
        }
        
        // Return the embedded byte map for later use
        // The structure indices should point to the newly added embedded structures
        const embeddedByteMap = tempDecoder.byteMap.map(mapping => ({
            ...mapping,
            offset: mapping.offset, // Keep 0-based offset for decrypted content
            structureIndex: mapping.structureIndex + structuresLengthBefore
        }));
        
        // Restore state
        this.offset = savedOffset;
        this.bytes = savedBytes;
        
        return embeddedByteMap;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CBORVisualizer, CBORVisualizationDecoder };
}