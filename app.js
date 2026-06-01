
/**
 * EMV TLV Parser Logic
 * Handles hex parsing, TLV structure traversal, and UI rendering.
 */

// --- EMV Tag Dictionary (Subset of common tags) ---
const EMV_TAGS = {
    "4F": "Application Identifier (AID)",
    "50": "Application Label",
    "57": "Track 2 Equivalent Data",
    "5A": "Application Primary Account Number (PAN)",
    "5F20": "Cardholder Name",
    "5F24": "Application Expiration Date",
    "5F25": "Application Effective Date",
    "5F2D": "Language Preference",
    "5F30": "Service Code",
    "5F34": "Application Primary Account Number Sequence Number",
    "6F": "File Control Information (FCI) Template",
    "70": "READ RECORD Response Message Template",
    "77": "Response Message Template Format 2",
    "80": "Response Message Template Format 1",
    "82": "Application Interchange Profile",
    "83": "Command Template",
    "84": "Dedicated File (DF) Name",
    "86": "Issuer Script Command",
    "87": "Application Priority Indicator",
    "88": "Short File Identifier (SFI)",
    "8A": "Authorisation Response Code",
    "8C": "Card Risk Management Data Object List 1 (CDOL1)",
    "8D": "Card Risk Management Data Object List 2 (CDOL2)",
    "8E": "Cardholder Verification Method (CVM) List",
    "8F": "Certification Authority Public Key Index",
    "90": "Issuer Public Key Certificate",
    "91": "Issuer Authentication Data",
    "92": "Issuer Public Key Remainder",
    "93": "Signed Static Application Data",
    "94": "Application File Locator (AFL)",
    "95": "Terminal Verification Results (TVR)",
    "97": "Transaction Certificate Data Object List (TDOL)",
    "98": "Transaction Certificate (TC) Hash Value",
    "99": "Transaction Personal Identification Number (PIN) Data",
    "9A": "Transaction Date",
    "9B": "Transaction Status Information",
    "9C": "Transaction Type",
    "9D": "Directory Definition File (DDF) Name",
    "9F01": "Acquirer Identifier",
    "9F02": "Amount, Authorised (Numeric)",
    "9F03": "Amount, Other (Numeric)",
    "9F04": "Amount, Other (Binary)",
    "9F05": "Application Discretionary Data",
    "9F06": "Application Identifier (AID) - Terminal",
    "9F07": "Application Usage Control",
    "9F08": "Application Version Number",
    "9F09": "Application Version Number",
    "9F0D": "Issuer Action Code - Default",
    "9F0E": "Issuer Action Code - Denial",
    "9F0F": "Issuer Action Code - Online",
    "9F10": "Issuer Application Data",
    "9F11": "Issuer Code Table Index",
    "9F12": "Application Preferred Name",
    "9F13": "Last Online Application Transaction Counter (ATC) Register",
    "9F14": "Lower Consecutive Offline Limit",
    "9F15": "Merchant Category Code",
    "9F16": "Merchant Identifier",
    "9F17": "Personal Identification Number (PIN) Try Counter",
    "9F18": "Issuer Script Identifier",
    "9F1A": "Terminal Country Code",
    "9F1B": "Terminal Floor Limit",
    "9F1C": "Terminal Identification",
    "9F1D": "Terminal Risk Management Data",
    "9F1E": "Interface Device (IFD) Serial Number",
    "9F1F": "Track 1 Discretionary Data",
    "9F20": "Track 2 Discretionary Data",
    "9F21": "Transaction Time",
    "9F22": "Certification Authority Public Key Index",
    "9F23": "Upper Consecutive Offline Limit",
    "9F26": "Application Cryptogram",
    "9F27": "Cryptogram Information Data",
    "9F2D": "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent",
    "9F2E": "Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder",
    "9F2F": "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate",
    "9F32": "Issuer Public Key Exponent",
    "9F33": "Terminal Capabilities",
    "9F34": "Cardholder Verification Method (CVM) Results",
    "9F35": "Terminal Type",
    "9F36": "Application Transaction Counter (ATC)",
    "9F37": "Unpredictable Number",
    "9F38": "Processing Options Data Object List (PDOL)",
    "9F39": "Point-of-Service (POS) Entry Mode",
    "9F40": "Additional Terminal Capabilities",
    "9F41": "Transaction Sequence Counter",
    "9F42": "Application Currency Code",
    "9F43": "Application Reference Currency",
    "9F44": "Application Currency Exponent",
    "9F45": "Data Authentication Code",
    "9F46": "Static Data Authentication Tag List",
    "9F47": "Signed Dynamic Application Data",
    "9F48": "Dynamic Data Authentication Tag List",
    "9F49": "Dynamic Data Object List (DDOL)",
    "9F4A": "Static Data Authentication Tag List",
    "9F4B": "Signed Dynamic Application Data",
    "9F4C": "ICC Dynamic Number",
    "9F4D": "Log Entry",
    "9F4E": "Merchant Name and Location",
    "9F4F": "Log Format",
    "9F53": "Consecutive Transaction Limit (International - Country)",
    "9F54": "Cumulative Total Transaction Amount Upper Limit",
    "9F55": "Geographic Indicator",
    "9F56": "Issuer Authentication Indicator",
    "9F57": "Issuer Country Code for Authorization",
    "9F58": "Lower Consecutive Offline Limit (International)",
    "9F59": "Upper Consecutive Offline Limit (International)",
    "9F5A": "Application Program Identifier (API)",
    "9F5B": "Issuer Script Results",
    "9F5C": "Cumulative Total Transaction Amount",
    "9F5D": "Available Offline Spending Amount",
    "9F5E": "Consecutive Transaction Limit (International - Country)",
    "9F5F": "Application Version Number",
    "BF0C": "File Control Information (FCI) Issuer Discretionary Data"
};

class EMVParserApp {
    constructor() {
        this.inputEl = document.getElementById('hexInput');
        this.resultContainer = document.getElementById('resultContainer');
        this.historyList = document.getElementById('historyList');
        this.stats = {
            tags: document.getElementById('statTags'),
            length: document.getElementById('statLength'),
            status: document.getElementById('statStatus')
        };
        
        this.init();
    }

    init() {
        this.loadHistory();
        // Auto-resize textarea logic could go here if needed
    }

    // --- Core Parsing Logic ---

    parseHex(hexString) {
        // Clean input: remove spaces, newlines, non-hex chars
        const cleanHex = hexString.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
        if (cleanHex.length === 0) return null;
        if (cleanHex.length % 2 !== 0) throw new Error("Invalid Hex Length: Must be even.");

        const bytes = [];
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes.push(parseInt(cleanHex.substr(i, 2), 16));
        }
        return bytes;
    }

    parseTLV(bytes, offset = 0, length = null) {
        const results = [];
        const endOffset = length !== null ? offset + length : bytes.length;

        while (offset < endOffset) {
            if (offset >= bytes.length) break;

            // 1. Parse Tag
            let tagBytes = [];
            let tagByte = bytes[offset];
            tagBytes.push(tagByte);
            offset++;

            // Check for multi-byte tag (bits 5-1 of first byte are 11111)
            if ((tagByte & 0x1F) === 0x1F) {
                while (offset < bytes.length) {
                    const nextByte = bytes[offset];
                    tagBytes.push(nextByte);
                    offset++;
                    if ((nextByte & 0x80) === 0) break; // High bit 0 means end of tag
                }
            }

            const tagHex = tagBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');

            // 2. Parse Length
            if (offset >= bytes.length) throw new Error(`Unexpected end of data after Tag ${tagHex}`);
            
            let lenByte = bytes[offset];
            offset++;
            let valueLength = 0;

            if ((lenByte & 0x80) === 0) {
                // Short form
                valueLength = lenByte;
            } else {
                // Long form
                const numLenBytes = lenByte & 0x7F;
                if (numLenBytes > 4) throw new Error(`Unsupported length field size at Tag ${tagHex}`);
                
                valueLength = 0;
                for (let i = 0; i < numLenBytes; i++) {
                    if (offset >= bytes.length) throw new Error(`Unexpected end of data in length field at Tag ${tagHex}`);
                    valueLength = (valueLength << 8) | bytes[offset];
                    offset++;
                }
            }

            // 3. Parse Value
            if (offset + valueLength > bytes.length) {
                 // Handle truncated data gracefully or throw error depending on strictness
                 // For demo, we'll take what's available but mark it
                 console.warn(`Truncated value for tag ${tagHex}`);
            }
            
            const valueBytes = bytes.slice(offset, offset + valueLength);
            offset += valueLength;

            // Construct Node
            const node = {
                tag: tagHex,
                name: EMV_TAGS[tagHex] || "Unknown Tag",
                length: valueLength,
                rawValue: valueBytes,
                ascii: this.bytesToAscii(valueBytes),
                hex: valueBytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
                children: []
            };

            // Recursive parsing for constructed tags (Bit 6 of first tag byte is 1)
            // Common constructed tags: 6F, 70, 77, A5, BF0C, etc.
            // Simple heuristic: if bit 6 is set, it's constructed.
            if ((tagBytes & 0x20) !== 0) {
                try {
                    node.children = this.parseTLV(valueBytes, 0, valueLength);
                } catch (e) {
                    // If recursive parse fails, treat as primitive
                    console.warn(`Failed to parse constructed tag ${tagHex} as TLV, treating as primitive.`);
                }
            }

            results.push(node);
        }
        return results;
    }

    bytesToAscii(bytes) {
        return bytes.map(b => {
            if (b >= 32 && b <= 126) return String.fromCharCode(b);
            return '.';
        }).join('');
    }

    // --- UI Rendering ---

    renderTree(nodes, container, depth = 0) {
        container.innerHTML = '';
        if (!nodes || nodes.length === 0) {
            container.innerHTML = '<div class="text-slate-400 italic">No valid TLV structure found.</div>';
            return;
        }

        const ul = document.createElement('ul');
        ul.className = 'space-y-1';
        
        nodes.forEach(node => {
            const li = document.createElement('li');
            li.className = 'relative pl-6 py-1';
            
            // Connector lines
            if (depth > 0) {
                const line = document.createElement('div');
                line.className = 'absolute left-0 top-0 bottom-0 w-px bg-slate-300';
                // Adjust line height to not overlap with sibling connectors visually if needed, 
                // but simple full height usually works for tree views
                li.appendChild(line);
                
                const connector = document.createElement('div');
                connector.className = 'absolute left-0 top-4 w-4 h-px bg-slate-300';
                li.appendChild(connector);
            }

            // Node Content
            const content = document.createElement('div');
            content.className = 'group flex flex-wrap items-start gap-2 p-2 rounded hover:bg-white hover:shadow-sm border border-transparent hover:border-slate-200 transition-all cursor-default';
            
            // Tag Badge
            const tagBadge = document.createElement('span');
            tagBadge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-bold font-mono ${this.isKnownTag(node.tag) ? 'bg-brand-100 text-brand-700' : 'bg-slate-200 text-slate-600'}`;
            tagBadge.textContent = node.tag;
            
            // Name
            const nameSpan = document.createElement('span');
            nameSpan.className = 'text-sm font-medium text-slate-700';
            nameSpan.textContent = node.name;

            // Meta Info (Length)
            const metaSpan = document.createElement('span');
            metaSpan.className = 'text-xs text-slate-400 font-mono';
            metaSpan.textContent = `[${node.length} bytes]`;

            // Value Preview (if primitive)
            let valuePreview = document.createElement('span');
            if (node.children.length === 0) {
                valuePreview.className = 'text-xs text-slate-500 font-mono break-all ml-2 bg-slate-50 px-1 rounded border border-slate-100 max-w-full truncate';
                valuePreview.title = node.hex;
                valuePreview.textContent = node.ascii.length > 0 ? `"${node.ascii}"` : node.hex.substring(0, 20) + (node.hex.length > 20 ? '...' : '');
            }

            content.appendChild(tagBadge);
            content.appendChild(nameSpan);
            content.appendChild(metaSpan);
            if (valuePreview) content.appendChild(valuePreview);

            li.appendChild(content);

            // Recurse
            if (node.children.length > 0) {
                const childContainer = document.createElement('div');
                childContainer.className = 'mt-1 ml-2'; // Indentation
                this.renderTree(node.children, childContainer, depth + 1);
                li.appendChild(childContainer);
            }

            ul.appendChild(li);
        });

        container.appendChild(ul);
    }

    isKnownTag(tag) {
        return EMV_TAGS.hasOwnProperty(tag);
    }

    // --- Actions ---

    parse() {
        const input = this.inputEl.value.trim();
        if (!input) {
            this.showError("请输入 HEX 数据");
            return;
        }

        try {
            this.stats.status.textContent = "Parsing...";
            this.stats.status.className = "text-sm font-bold text-yellow-600 mt-1 bg-yellow-50 px-2 py-1 rounded-full";
            
            // Small delay to allow UI update
            setTimeout(() => {
                try {
                    const bytes = this.parseHex(input);
                    const result = this.parseTLV(bytes);
                    
                    this.renderTree(result, this.resultContainer);
                    this.updateStats(result, bytes.length);
                    this.addToHistory(input.substring(0, 30) + "...", result.length);
                    
                    this.stats.status.textContent = "Success";
                    this.stats.status.className = "text-sm font-bold text-emerald-600 mt-1 bg-emerald-50 px-2 py-1 rounded-full";
                } catch (e) {
                    this.showError(e.message);
                }
            }, 50);

        } catch (e) {
            this.showError(e.message);
        }
    }

    updateStats(nodes, totalBytes) {
        // Count total tags recursively
        let count = 0;
        const countTags = (n) => {
            n.forEach(node => {
                count++;
                if (node.children.length > 0) countTags(node.children);
            });
        };
        countTags(nodes);

        this.stats.tags.textContent = count;
        this.stats.length.textContent = `${totalBytes} B`;
    }

    showError(msg) {
        this.resultContainer.innerHTML = `
            <div class="flex flex-col items-center justify-center h-64 text-red-500 fade-in">
                <i class="fa-solid fa-circle-exclamation text-4xl mb-3"></i>
                <p class="font-medium">解析错误</p>
                <p class="text-sm text-slate-500 mt-1">${msg}</p>
            </div>
        `;
        this.stats.status.textContent = "Error";
        this.stats.status.className = "text-sm font-bold text-red-600 mt-1 bg-red-50 px-2 py-1 rounded-full";
    }

    formatInput() {
        let val = this.inputEl.value;
        // Remove non-hex
        val = val.replace(/[^0-9A-Fa-f]/g, '');
        // Add spaces every 2 chars
        val = val.match(/.{1,2}/g)?.join(' ') || '';
        // Wrap lines every 16 bytes (32 chars + 15 spaces = 47 chars approx)
        // Simple approach: just insert newlines every 48 chars of the spaced string
        const formatted = val.match(/.{1,48}/g)?.join('\n') || '';
        this.inputEl.value = formatted;
    }

    async pasteFromClipboard() {
        try {
            const text = await navigator.clipboard.readText();
            this.inputEl.value = text;
        } catch (err) {
            alert('无法访问剪贴板，请手动粘贴');
        }
    }

    loadSample() {
        // Sample EMV FCI Template
        const sample = "6F 3B 84 0E A0 00 00 00 03 10 10 01 00 00 00 00 00 00 A5 29 50 0A 56 49 53 41 20 43 52 45 44 49 54 87 01 01 5F 2D 02 65 6E 9F 11 01 01 5F 24 03 25 12 31 5F 25 03 15 01 01 9F 07 02 FF 00";
        this.inputEl.value = sample;
        this.parse();
    }

    clearAll() {
        this.inputEl.value = '';
        this.resultContainer.innerHTML = `
            <div class="flex flex-col items-center justify-center h-64 text-slate-400">
                <i class="fa-solid fa-layer-group text-4xl mb-3 opacity-20"></i>
                <p>等待数据输入...</p>
            </div>
        `;
        this.stats.tags.textContent = '0';
        this.stats.length.textContent = '0 B';
        this.stats.status.textContent = 'Ready';
        this.stats.status.className = "text-sm font-bold text-emerald-600 mt-1 bg-emerald-50 px-2 py-1 rounded-full";
    }

    // --- History Management ---

    addToHistory(preview, tagCount) {
        let history = JSON.parse(localStorage.getItem('emv_history') || '[]');
        const newItem = {
            date: new Date().toLocaleTimeString(),
            preview: preview,
            tagCount: tagCount
        };
        history.unshift(newItem);
        if (history.length > 10) history.pop();
        localStorage.setItem('emv_history', JSON.stringify(history));
        this.loadHistory();
    }

    loadHistory() {
        const history = JSON.parse(localStorage.getItem('emv_history') || '[]');
        const list = this.historyList;
        list.innerHTML = '';

        if (history.length === 0) {
            list.innerHTML = '<li class="p-4 text-center text-slate-400 text-sm italic">暂无历史记录</li>';
            return;
        }

        history.forEach(item => {
            const li = document.createElement('li');
            li.className = 'p-3 hover:bg-slate-50 cursor-pointer transition-colors border-b border-slate-50 last:border-0 flex justify-between items-center group';
            li.innerHTML = `
                <div class="flex flex-col">
                    <span class="text-xs font-mono text-slate-600 truncate max-w-[200px]">${item.preview}</span>
                    <span class="text-[10px] text-slate-400">${item.date} • ${item.tagCount} Tags</span>
                </div>
                <i class="fa-solid fa-chevron-right text-slate-300 group-hover:text-brand-500 text-xs"></i>
            `;
            // Click to restore (simplified: just puts preview back, ideally would store full hex)
            // For this demo, we won't store full hex in history to save space, just visual feedback
            list.appendChild(li);
        });
    }

    clearHistory() {
        localStorage.removeItem('emv_history');
        this.loadHistory();
    }

    // --- Export ---

    exportJSON() {
        // Re-parse to get clean object
        const input = this.inputEl.value.trim();
        if (!input) return;
        try {
            const bytes = this.parseHex(input);
            const result = this.parseTLV(bytes);
            const jsonStr = JSON.stringify(result, null, 2);
            
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'emv_parsed.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (e) {
            alert("无法导出：数据解析失败");
        }
    }

    copyResult() {
        // Copy the text content of the result container
        const text = this.resultContainer.innerText;
        navigator.clipboard.writeText(text).then(() => {
            const btn = document.querySelector('button[onclick="app.copyResult()"]');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check"></i> 已复制';
            setTimeout(() => btn.innerHTML = originalHtml, 2000);
        });
    }
}

// Initialize App
const app = new EMVParserApp();
