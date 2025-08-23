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
            const decoder = new CBORVisualizationDecoder(Array.from(bytes));
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
        
        bytes.forEach((byte, index) => {
            const byteElement = document.createElement('span');
            byteElement.className = 'cbor-byte';
            byteElement.textContent = byte.toString(16).padStart(2, '0').toUpperCase();
            byteElement.dataset.offset = index;
            
            const mapEntry = this.currentByteMap.find(m => m.offset === index);
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
            
            container.appendChild(byteElement);
        });
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
                
                // Highlight related bytes
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
        
        if (onHighlight) {
            onHighlight(value, source);
        }
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
                
                // Highlight related bytes and scroll first byte into view
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
    constructor(bytes) {
        this.bytes = bytes;
        this.offset = 0;
        this.structures = [];
        this.byteMap = [];
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
                
                // Check if this is a CWT claim key
                if (context === 'cwt-key' || context === 'cose-header-key') {
                    const claimName = this.getCWTClaimName(value);
                    if (claimName) {
                        structure.description += ` [${claimName}]`;
                    }
                }
                structure.endOffset = this.offset - 1;
                break;

            case 1: // Negative integer
                structure.description = `Negative Integer: ${-1 - value}`;
                
                // Check for COSE header parameters (negative integers)
                if (context === 'cose-header-key') {
                    const headerParam = this.getCOSEHeaderParam(-1 - value);
                    if (headerParam) {
                        structure.description += ` [${headerParam}]`;
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
                    
                    // Save the key offset to potentially get its value
                    const keyStartOffset = this.offset;
                    this.decodeItem(indent + 2, keyContext);
                    
                    this.structures.push({
                        indent: indent + 1,
                        startOffset: this.offset,
                        endOffset: null,
                        description: `Value ${i}:`
                    });
                    this.decodeItem(indent + 2);
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
    
    decodeEmbeddedCBOR(embeddedBytes, indent, context, baseOffset) {
        // Save current state
        const savedOffset = this.offset;
        const savedBytes = this.bytes;
        const savedByteMap = [...this.byteMap];
        
        // Create a temporary decoder for the embedded CBOR
        const tempDecoder = new CBORVisualizationDecoder(Array.from(embeddedBytes));
        tempDecoder.byteMap = [];
        tempDecoder.structures = [];
        
        // Decode the embedded structure
        tempDecoder.decodeItem(0, context);
        
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
                structureIndex: mapping.structureIndex + this.structures.length - tempDecoder.structures.length
            });
        }
        
        // Restore state
        this.offset = savedOffset;
        this.bytes = savedBytes;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CBORVisualizer, CBORVisualizationDecoder };
}