
// EMV TLV Parser Application Logic

let currentFormat = 'hex';
let parsedData = [];

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    const input = document.getElementById('tlv-input');
    const autoParse = document.getElementById('auto-parse');
    
    input.addEventListener('input', function() {
        if (autoParse.checked) {
            parseTLV();
        }
    });
    
    // Load any saved data
    const saved = localStorage.getItem('tlv-input');
    if (saved) {
        input.value = saved;
        if (autoParse.checked) {
            parseTLV();
        }
    }
});

function setInputFormat(format) {
    currentFormat = format;
    document.getElementById('btn-hex').className = format === 'hex' 
        ? 'px-3 py-1 rounded text-xs font-medium bg-blue-600 text-white'
        : 'px-3 py-1 rounded text-xs font-medium bg-gray-700 text-gray-300';
    document.getElementById('btn-base64').className = format === 'base64'
        ? 'px-3 py-1 rounded text-xs font-medium bg-blue-600 text-white'
        : 'px-3 py-1 rounded text-xs font-medium bg-gray-700 text-gray-300';
    document.getElementById('info-format').textContent = format.toUpperCase();
    
    if (document.getElementById('auto-parse').checked) {
        parseTLV();
    }
}

function insertTag(tag) {
    const input = document.getElementById('tlv-input');
    const cursorPos = input.selectionStart;
    const textBefore = input.value.substring(0, cursorPos);
    const textAfter = input.value.substring(cursorPos);
    
    // Add some spacing if needed
    const prefix = textBefore.length > 0 && !textBefore.endsWith('\n') && !textBefore.endsWith(' ') ? ' ' : '';
    
    input.value = textBefore + prefix + tag;
    input.focus();
    input.setSelectionRange(cursorPos + prefix.length + tag.length, cursorPos + prefix.length + tag.length);
    
    if (document.getElementById('auto-parse').checked) {
        parseTLV();
    }
}

function loadExample() {
    const example = '9F02060000000010009F03060000000000009F1A0201565F2A0201569A032105269C01005F3401019F3303E0F8C8';
    document.getElementById('tlv-input').value = example;
    setInputFormat('hex');
    parseTLV();
}

function clearAll() {
    document.getElementById('tlv-input').value = '';
    document.getElementById('parsed-output').innerHTML = `
        <div class="text-center text-gray-500 py-20">
            <i class="fas fa-inbox text-4xl mb-4 opacity-50"></i>
            <p>请输入 TLV 数据并点击解析</p>
        </div>
    `;
    document.getElementById('hex-view').innerHTML = `
        <div class="text-center text-gray-500 py-8">
            <p>解析后将显示详细的十六进制视图</p>
        </div>
    `;
    updateInfo(0, 0, '等待输入');
    localStorage.removeItem('tlv-input');
}

function parseTLV() {
    const input = document.getElementById('tlv-input').value.trim();
    if (!input) {
        clearAll();
        return;
    }
    
    // Save to localStorage
    localStorage.setItem('tlv-input', input);
    
    let bytes;
    try {
        if (currentFormat === 'hex') {
            bytes = hexToBytes(input);
        } else {
            bytes = base64ToBytes(input);
        }
    } catch (e) {
        showError('数据格式错误: ' + e.message);
        return;
    }
    
    updateInfo(bytes.length, 0, '解析中...');
    
    try {
        parsedData = parseTLVBytes(bytes, 0, bytes.length);
        renderParsedResult(parsedData);
        renderHexView(bytes, parsedData);
        updateInfo(bytes.length, countTLVElements(parsedData), '解析成功');
    } catch (e) {
        showError('解析错误: ' + e.message);
    }
}

function hexToBytes(hex) {
    // Remove spaces and newlines
    hex = hex.replace(/\s/g, '');
    
    if (hex.length % 2 !== 0) {
        throw new Error('HEX 字符串长度必须为偶数');
    }
    
    if (!/^[0-9A-Fa-f]+$/.test(hex)) {
        throw new Error('包含无效的 HEX 字符');
    }
    
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function parseTLVBytes(bytes, offset, length) {
    const results = [];
    let pos = offset;
    const end = offset + length;
    
    while (pos < end) {
        if (pos >= bytes.length) break;
        
        // Parse Tag
        const tagResult = parseTag(bytes, pos);
        pos = tagResult.nextPos;
        
        if (pos >= bytes.length) {
            throw new Error('数据不完整: 缺少长度字段');
        }
        
        // Parse Length
        const lengthResult = parseLength(bytes, pos);
        pos = lengthResult.nextPos;
        const valueLength = lengthResult.value;
        
        if (pos + valueLength > bytes.length) {
            throw new Error(`数据不完整: Tag ${tagResult.tagHex} 需要 ${valueLength} 字节，但只剩 ${bytes.length - pos} 字节`);
        }
        
        // Extract Value
        const valueBytes = bytes.slice(pos, pos + valueLength);
        pos += valueLength;
        
        const tlvElement = {
            tag: tagResult.tagHex,
            tagBytes: tagResult.tagBytes,
            length: valueLength,
            lengthBytes: lengthResult.lengthBytes,
            value: valueBytes,
            valueHex: bytesToHex(valueBytes),
            valueAscii: bytesToAscii(valueBytes),
            isConstructed: tagResult.isConstructed,
            children: []
        };
        
        // If constructed, parse children
        if (tlvElement.isConstructed && valueLength > 0) {
            try {
                tlvElement.children = parseTLVBytes(valueBytes, 0, valueLength);
            } catch (e) {
                // If parsing children fails, keep as primitive
                tlvElement.isConstructed = false;
            }
        }
        
        results.push(tlvElement);
    }
    
    return results;
}

function parseTag(bytes, offset) {
    let pos = offset;
    let tagByte = bytes[pos];
    let tagHex = padHex(tagByte);
    let isConstructed = (tagByte & 0x20) !== 0;
    
    // Check if tag is multi-byte
    if ((tagByte & 0x1F) === 0x1F) {
        pos++;
        if (pos >= bytes.length) {
            throw new Error('数据不完整: Tag 字节缺失');
        }
        tagByte = bytes[pos];
        tagHex += padHex(tagByte);
        
        // Continue reading while bit 8 is set
        while ((tagByte & 0x80) !== 0) {
            pos++;
            if (pos >= bytes.length) {
                throw new Error('数据不完整: Tag 字节缺失');
            }
            tagByte = bytes[pos];
            tagHex += padHex(tagByte);
        }
    }
    
    return {
        tagHex: tagHex.toUpperCase(),
        tagBytes: bytes.slice(offset, pos + 1),
        isConstructed: isConstructed,
        nextPos: pos + 1
    };
}

function parseLength(bytes, offset) {
    let pos = offset;
    let lengthByte = bytes[pos];
    let lengthBytes = [lengthByte];
    let value;
    
    if ((lengthByte & 0x80) === 0) {
        // Short form
        value = lengthByte;
        pos++;
    } else {
        // Long form
        const numBytes = lengthByte & 0x7F;
        if (numBytes === 0) {
            throw new Error('不支持 indefinite length');
        }
        if (numBytes > 4) {
            throw new Error('长度字段过长');
        }
        
        pos++;
        value = 0;
        for (let i = 0; i < numBytes; i++) {
            if (pos >= bytes.length) {
                throw new Error('数据不完整: 长度字节缺失');
            }
            value = (value << 8) | bytes[pos];
            lengthBytes.push(bytes[pos]);
            pos++;
        }
    }
    
    return {
        value: value,
        lengthBytes: new Uint8Array(lengthBytes),
        nextPos: pos
    };
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => padHex(b)).join('').toUpperCase();
}

function bytesToAscii(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
        const code = bytes[i];
        if (code >= 32 && code <= 126) {
            result += String.fromCharCode(code);
        } else {
            result += '.';
        }
    }
    return result;
}

function padHex(byte) {
    return byte.toString(16).padStart(2, '0');
}

function countTLVElements(elements) {
    let count = elements.length;
    for (const elem of elements) {
        if (elem.children && elem.children.length > 0) {
            count += countTLVElements(elem.children);
        }
    }
    return count;
}

function renderParsedResult(elements, level = 0) {
    const container = document.getElementById('parsed-output');
    const showAscii = document.getElementById('show-ascii').checked;
    
    if (level === 0) {
        container.innerHTML = '';
    }
    
    if (elements.length === 0 && level === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-500 py-20">
                <i class="fas fa-check-circle text-4xl mb-4 text-green-500"></i>
                <p>解析完成，但没有找到 TLV 元素</p>
            </div>
        `;
        return;
    }
    
    const div = document.createElement('div');
    div.className = 'animate-fade-in';
    
    elements.forEach((elem, index) => {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'mb-2 hover-row rounded-lg p-3 transition-all';
        if (level > 0) {
            itemDiv.style.marginLeft = (level * 20) + 'px';
            itemDiv.style.borderLeft = '2px solid rgba(96, 165, 250, 0.3)';
        }
        
        const tagDesc = getTagDescription(elem.tag);
        
        itemDiv.innerHTML = `
            <div class="flex items-start justify-between">
                <div class="flex-1">
                    <div class="flex items-center space-x-2 mb-1">
                        <span class="tlv-tag mono-font text-sm">${elem.tag}</span>
                        ${elem.isConstructed ? '<span class="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded">构造型</span>' : ''}
                        ${tagDesc ? `<span class="text-xs text-gray-500">${tagDesc}</span>` : ''}
                    </div>
                    <div class="flex items-center space-x-4 text-xs">
                        <span class="text-gray-500">长度: <span class="tlv-length mono-font">${elem.length}</span> 字节</span>
                        ${!elem.isConstructed ? `
                            <span class="text-gray-500">值: <span class="tlv-value mono-font">${elem.valueHex}</span></span>
                            ${showAscii ? `<span class="text-gray-500">ASCII: <span class="tlv-value-ascii mono-font">${elem.valueAscii}</span></span>` : ''}
                        ` : ''}
                    </div>
                </div>
                <button onclick="copyValue('${elem.valueHex}')" class="text-gray-500 hover:text-blue-400 transition" title="复制值">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        `;
        
        div.appendChild(itemDiv);
        
        // Render children if constructed
        if (elem.isConstructed && elem.children && elem.children.length > 0) {
            const childrenDiv = document.createElement('div');
            childrenDiv.className = 'mt-2';
            div.appendChild(childrenDiv);
            renderParsedResultToContainer(elem.children, childrenDiv, level + 1);
        }
    });
    
    if (level === 0) {
        container.appendChild(div);
    } else {
        return div;
    }
}

function renderParsedResultToContainer(elements, container, level) {
    const showAscii = document.getElementById('show-ascii').checked;
    
    elements.forEach((elem, index) => {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'mb-2 hover-row rounded-lg p-3 transition-all';
        if (level > 0) {
            itemDiv.style.marginLeft = (level * 20) + 'px';
            itemDiv.style.borderLeft = '2px solid rgba(96, 165, 250, 0.3)';
        }
        
        const tagDesc = getTagDescription(elem.tag);
        
        itemDiv.innerHTML = `
            <div class="flex items-start justify-between">
                <div class="flex-1">
                    <div class="flex items-center space-x-2 mb-1">
                        <span class="tlv-tag mono-font text-sm">${elem.tag}</span>
                        ${elem.isConstructed ? '<span class="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded">构造型</span>' : ''}
                        ${tagDesc ? `<span class="text-xs text-gray-500">${tagDesc}</span>` : ''}
                    </div>
                    <div class="flex items-center space-x-4 text-xs">
                        <span class="text-gray-500">长度: <span class="tlv-length mono-font">${elem.length}</span> 字节</span>
                        ${!elem.isConstructed ? `
                            <span class="text-gray-500">值: <span class="tlv-value mono-font">${elem.valueHex}</span></span>
                            ${showAscii ? `<span class="text-gray-500">ASCII: <span class="tlv-value-ascii mono-font">${elem.valueAscii}</span></span>` : ''}
                        ` : ''}
                    </div>
                </div>
                <button onclick="copyValue('${elem.valueHex}')" class="text-gray-500 hover:text-blue-400 transition" title="复制值">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        `;
        
        container.appendChild(itemDiv);
        
        // Render children if constructed
        if (elem.isConstructed && elem.children && elem.children.length > 0) {
            const childrenDiv = document.createElement('div');
            childrenDiv.className = 'mt-2';
            container.appendChild(childrenDiv);
            renderParsedResultToContainer(elem.children, childrenDiv, level + 1);
        }
    });
}

function renderHexView(bytes, tlvElements) {
    const container = document.getElementById('hex-view');
    const lines = [];
    const bytesPerLine = 16;
    
    for (let i = 0; i < bytes.length; i += bytesPerLine) {
        const chunk = bytes.slice(i, Math.min(i + bytesPerLine, bytes.length));
        const hexPart = Array.from(chunk).map(b => padHex(b)).join(' ').toUpperCase();
        const asciiPart = Array.from(chunk).map(b => {
            const code = b;
            return (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
        }).join('');
        
        const offset = padHex(Math.floor(i / 16)).padStart(8, '0').toUpperCase();
        lines.push(`<div class="flex"><span class="text-gray-600 w-24 mono-font">${offset}</span><span class="mono-font text-blue-300 flex-1">${hexPart.padEnd(47)}</span><span class="text-gray-500 mono-font ml-4">${asciiPart}</span></div>`);
    }
    
    container.innerHTML = lines.join('');
}

function getTagDescription(tag) {
    const descriptions = {
        '9F02': '授权金额 (Amount, Authorized)',
        '9F03': '其他金额 (Amount, Other)',
        '9F1A': '国家代码 (Country Code)',
        '5F2A': '交易货币代码 (Transaction Currency Code)',
        '9A': '交易日期 (Transaction Date)',
        '9C': '交易类型 (Transaction Type)',
        '5F34': '应用 PAN 序列号 (Application PAN Sequence Number)',
        '9F33': '终端能力 (Terminal Capabilities)',
        '9F34': '持卡人验证方法结果 (CVM Results)',
        '9F35': '终端类型 (Terminal Type)',
        '9F36': '应用交易计数器 (Application Transaction Counter)',
        '9F37': '不可预测数 (Unpredictable Number)',
        '9F41': '交易序列计数器 (Transaction Sequence Counter)',
        '5F20': '持卡人姓名 (Cardholder Name)',
        '5F24': '应用到期日期 (Application Expiration Date)',
        '5F25': '应用生效日期 (Application Effective Date)',
        '5F28': '发卡行国家代码 (Issuer Country Code)',
        '5F30': '服务代码 (Service Code)',
        '5F36': '交易货币指数 (Transaction Currency Exponent)',
        '9F07': '应用使用控制 (Application Usage Control)',
        '9F08': '应用版本号 (Application Version Number)',
        '9F09': '应用版本号 (Application Version Number)',
        '9F0D': '发卡行行为代码 (Issuer Action Code - Default)',
        '9F0E': '发卡行行为代码 (Issuer Action Code - Denial)',
        '9F0F': '发卡行行为代码 (Issuer Action Code - Online)',
        '9F10': '发卡行应用数据 (Issuer Application Data)',
        '9F11': '发卡行代码表索引 (Issuer Code Table Index)',
        '9F12': '应用首选名称 (Application Preferred Name)',
        '9F13': '最后在线 ATC 注册 (Last Online ATC Register)',
        '9F14': '最低离线金额限制 (Lower Consecutive Offline Limit)',
        '9F15': '商户类别码 (Merchant Category Code)',
        '9F16': '商户标识符 (Merchant Identifier)',
        '9F17': 'PIN 尝试计数器 (PIN Try Counter)',
        '9F1B': '终端地板限制 (Terminal Floor Limit)',
        '9F1C': '终端标识符 (Terminal Identification)',
        '9F1D': '终端风险管理数据 (Terminal Risk Management Data)',
        '9F1E': '接口设备序列号 (Interface Device Serial Number)',
        '9F1F': '磁条轨道 1 数据 (Track 1 Discretionary Data)',
        '9F21': '交易时间 (Transaction Time)',
        '9F22': '认证中心公钥指数 (Certification Authority Public Key Exponent)',
        '9F23': '连续离线交易上限 (Upper Consecutive Offline Limit)',
        '9F26': '应用密文 (Application Cryptogram)',
        '9F27': '密文信息数据 (Cryptogram Information Data)',
        '9F2D': 'IC 卡 PIN 加密密钥 (ICC PIN Encipherment Public Key Exponent)',
        '9F2E': 'IC 卡 PIN 加密密钥 (ICC PIN Encipherment Public Key Remainder)',
        '9F2F': 'IC 卡 PIN 加密密钥 (ICC PIN Encipherment Public Key Modulus)',
        '9F32': '发卡行公钥指数 (Issuer Public Key Exponent)',
        '9F38': '处理选项数据对象列表 (Processing Options Data Object List - PDOL)',
        '9F39': 'POS 输入能力 (POS Entry Mode)',
        '9F3A': '金额参考货币 (Amount, Reference Currency)',
        '9F3B': '应用参考货币 (Application Reference Currency)',
        '9F3C': '交易参考货币代码 (Transaction Reference Currency Code)',
        '9F3D': '交易参考货币指数 (Transaction Reference Currency Exponent)',
        '9F40': '附加终端能力 (Additional Terminal Capabilities)',
        '9F42': '应用货币代码 (Application Currency Code)',
        '9F43': '应用货币指数 (Application Currency Exponent)',
        '9F44': '应用货币指数 (Application Currency Exponent)',
        '9F45': '数据认证码 (Data Authentication Code)',
        '9F46': 'IC 卡公钥证书 (ICC Public Key Certificate)',
        '9F47': 'IC 卡公钥指数 (ICC Public Key Exponent)',
        '9F48': 'IC 卡公钥余数 (ICC Public Key Remainder)',
        '9F49': '动态数据认证数据对象列表 (Dynamic Data Authentication Data Object List - DDOL)',
        '9F4A': '静态数据认证标签列表 (Static Data Authentication Tag List)',
        '9F4B': 'IC 卡动态数据签名 (ICC Dynamic Number)',
        '9F4C': 'IC 卡动态数据 (ICC Dynamic Data)',
        '9F4D': '日志条目 (Log Entry)',
        '9F4E': '商户名称和位置 (Merchant Name and Location)',
        '9F4F': '日志格式 (Log Format)',
        '50': '应用标签 (Application Label)',
        '57': '磁条轨道 2 等效数据 (Track 2 Equivalent Data)',
        '5A': '应用主账号 (Application Primary Account Number - PAN)',
        '5F2D': '语言偏好 (Language Preference)',
        '5F50': '发卡行 URL (Issuer URL)',
        '5F53': '国际 IBAN (International Bank Account Number - IBAN)',
        '5F54': '银行标识代码 (Bank Identifier Code - BIC)',
        '5F55': '发卡人国家代码 (Issuer Country Code - alpha2 format)',
        '5F56': '发卡人国家代码 (Issuer Country Code - alpha3 format)',
        '6F': '文件控制信息模板 (File Control Information - FCI Template)',
        '70': '记录模板 (Record Template)',
        '77': '响应消息模板 2 (Response Message Template Format 2)',
        '80': '响应消息模板 1 (Response Message Template Format 1)',
        '82': '应用 interchange 配置文件 (Application Interchange Profile - AIP)',
        '83': '命令模板 (Command Template)',
        '84': '专用文件名称 (Dedicated File Name - DFN)',
        '86': ' issuer 脚本命令 (Issuer Script Command)',
        '87': '应用优先指示器 (Application Priority Indicator)',
        '88': '短文件标识符 (Short File Identifier - SFI)',
        '89': '授权响应代码 (Authorisation Response Code)',
        '8A': '授权响应代码 (Authorisation Response Code)',
        '8C': '卡片风险管理数据对象列表 1 (Card Risk Management Data Object List 1 - CDOL1)',
        '8D': '卡片风险管理数据对象列表 2 (Card Risk Management Data Object List 2 - CDOL2)',
        '8E': '持卡人验证方法列表 (Cardholder Verification Method - CVM List)',
        '8F': '认证中心公钥索引 (Certification Authority Public Key Index)',
        '90': 'IC 卡公钥证书 (ICC Public Key Certificate)',
        '91': '发卡行认证数据 (Issuer Authentication Data)',
        '92': '发卡行公钥余数 (Issuer Public Key Remainder)',
        '93': '签名静态应用数据 (Signed Static Application Data)',
        '94': '应用文件定位器 (Application File Locator - AFL)',
        '95': '终端验证结果 (Terminal Verification Results - TVR)',
        '96': '交易证书哈希值 (Transaction Certificate Hash Value)',
        '97': '交易证书数据对象列表 (Transaction Certificate Data Object List - TDOL)',
        '98': '交易证书 (Transaction Certificate - TC)',
        '99': '交易个人识别码数据 (Transaction Personal Identification Number - PIN Data)',
        '9B': '交易状态信息 (Transaction Status Information)',
        '9D': '目录定义文件 (Directory Definition File - DDF)',
        'BF0C': '文件控制信息参数模板 (FCI Parameter Template)'
    };
    
    return descriptions[tag.toUpperCase()] || null;
}

function updateInfo(length, count, status) {
    document.getElementById('info-length').textContent = length + ' bytes';
    document.getElementById('info-count').textContent = count;
    
    const statusEl = document.getElementById('info-status');
    statusEl.textContent = status;
    
    if (status === '解析成功') {
        statusEl.className = 'text-sm font-medium text-green-400';
    } else if (status === '解析中...') {
        statusEl.className = 'text-sm font-medium text-yellow-400';
    } else if (status.startsWith('错误')) {
        statusEl.className = 'text-sm font-medium text-red-400';
    } else {
        statusEl.className = 'text-sm font-medium text-gray-400';
    }
}

function showError(message) {
    const container = document.getElementById('parsed-output');
    container.innerHTML = `
        <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-4 animate-fade-in">
            <div class="flex items-start">
                <i class="fas fa-exclamation-triangle text-red-400 mt-1 mr-3"></i>
                <div>
                    <h4 class="text-red-400 font-semibold mb-1">解析错误</h4>
                    <p class="text-red-300 text-sm">${message}</p>
                </div>
            </div>
        </div>
    `;
    updateInfo(0, 0, '错误: ' + message);
}

function copyValue(value) {
    navigator.clipboard.writeText(value).then(() => {
        showToast('已复制到剪贴板');
    }).catch(err => {
        console.error('复制失败:', err);
    });
}

function copyResult() {
    if (parsedData.length === 0) {
        showToast('没有可复制的数据');
        return;
    }
    
    const json = JSON.stringify(parsedData, null, 2);
    navigator.clipboard.writeText(json).then(() => {
        showToast('JSON 已复制到剪贴板');
    }).catch(err => {
        console.error('复制失败:', err);
    });
}

function exportJSON() {
    if (parsedData.length === 0) {
        showToast('没有可导出的数据');
        return;
    }
    
    const json = JSON.stringify(parsedData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'tlv-parsed-' + new Date().getTime() + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('JSON 文件已下载');
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'fixed bottom-4 right-4 bg-gray-800 text-white px-6 py-3 rounded-lg shadow-lg animate-fade-in z-50';
    toast.innerHTML = `<i class="fas fa-check-circle text-green-400 mr-2"></i>${message}`;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 2000);
}
