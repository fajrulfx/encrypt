function caesarCipher(str, shift, action) {
    let output = '';
    const adjust = action === 'encrypt' ? shift : -shift;

    for (let i = 0; i < str.length; i++) {
        let char = str[i];
        if (char.match(/[a-z]/i)) { // Check if the character is a letter
            const code = str.charCodeAt(i);
            let base = 'A'.charCodeAt(0);

            if (char == char.toLowerCase()) {
                base = 'a'.charCodeAt(0);
            }

            char = String.fromCharCode(((code - base + adjust) % 26 + 26) % 26 + base);
        }
        output += char;
    }
    return output;
}

function encryptText() {
    const inputText = document.getElementById('inputText').value;
    const shift = parseInt(document.getElementById('encryptShift').value);
    if (!isNaN(shift)) {
        const encryptedText = caesarCipher(inputText, shift, 'encrypt');
        document.getElementById('cipherText').value = encryptedText;
    }
}

function decryptText() {
    const cipherText = document.getElementById('cipherText').value;
    const shift = parseInt(document.getElementById('decryptShift').value);
    if (!isNaN(shift)) {
        const decryptedText = caesarCipher(cipherText, shift, 'decrypt');
        document.getElementById('resultText').value = decryptedText;
    }
}

document.getElementById('encryptShift').addEventListener('input', function() {
    encryptText();
    decryptText()
});
document.getElementById('inputText').addEventListener('input', function() {
    encryptText();
    decryptText()
});
document.getElementById('decryptShift').addEventListener('input', decryptText);
document.getElementById('cipherText').addEventListener('input', decryptText);

// AES

document.getElementById('generateKeyIv').addEventListener('click', async () => {
    const key = window.crypto.getRandomValues(new Uint8Array(16)); // 128-bit key
    const iv = window.crypto.getRandomValues(new Uint8Array(16));

    document.getElementById('key').value = Array.from(key).map(b => b.toString(16).padStart(2, '0'))
        .join('');
    document.getElementById('iv').value = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(
        '');
});

document.getElementById('encrypt').addEventListener('click', async () => {
    const plaintext = document.getElementById('plaintext').value;
    const keyHex = document.getElementById('key').value;
    const ivHex = document.getElementById('iv').value;

    const key = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        key, {
            name: 'AES-CBC'
        },
        false,
        ['encrypt']
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const paddedData = new Uint8Array(16 * Math.ceil(data.byteLength / 16));
    paddedData.set(data);

    const ciphertext = await window.crypto.subtle.encrypt({
            name: 'AES-CBC',
            iv
        },
        cryptoKey,
        paddedData
    );

    document.getElementById('ciphertext').value = btoa(String.fromCharCode(...new Uint8Array(
        ciphertext)));
});

document.getElementById('decrypt').addEventListener('click', async () => {
    const ciphertext = document.getElementById('ciphertext').value;
    const keyHex = document.getElementById('inputKey').value;
    const ivHex = document.getElementById('inputIv').value;

    // Validate key length (must be 128, 192, or 256 bits)
    if (keyHex.length !== 32 && keyHex.length !== 48 && keyHex.length !== 64) {
        alert('Invalid key length. AES key must be 128, 192, or 256 bits.');
        return;
    }

    const key = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const ciphertextBytes = new Uint8Array(atob(ciphertext).split('').map(c => c.charCodeAt(0)));

    try {
        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            key, {
                name: 'AES-CBC'
            },
            false,
            ['decrypt']
        );

        const decryptedData = await window.crypto.subtle.decrypt({
                name: 'AES-CBC',
                iv
            },
            cryptoKey,
            ciphertextBytes
        );

        const decoder = new TextDecoder();
        document.getElementById('decryptedtext').value = decoder.decode(decryptedData).replace(/\0/g,
            '');
    } catch (e) {
        // Output garbled text on decryption failure
        const decoder = new TextDecoder();
        document.getElementById('decryptedtext').value = decoder.decode(ciphertextBytes).replace(/\0/g,
            '');
    }
});
document.getElementById('pasteKey').addEventListener('click', function() {
    document.getElementById('inputKey').value = document.getElementById('key').value
    document.getElementById('inputIv').value = document.getElementById('iv').value
});

// RSA
let privateKey, publicKey;

function generateKeys() {
    const rsa = forge.pki.rsa;
    rsa.generateKeyPair({
        bits: 2048,
        e: 0x10001
    }, function(err, keypair) {
        privateKey = keypair.privateKey;
        publicKey = keypair.publicKey;

        document.getElementById('publicKey').value = forge.pki.publicKeyToPem(publicKey);
        document.getElementById('privateKey').value = forge.pki.privateKeyToPem(privateKey);
    });
}

function encryptMessage() {
    const message = document.getElementById('message').value;
    const encrypted = publicKey.encrypt(message, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create()
    });
    document.getElementById('encryptedMessage').value = forge.util.encode64(encrypted);
}

function decryptMessage() {
    const encryptedMessage = forge.util.decode64(document.getElementById('encryptedMessage').value);
    const privateKeyPem = document.getElementById('privateKeyInput').value;
    try {
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const decrypted = privateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf1.create()
        });
        document.getElementById('decryptedMessage').value = decrypted;
    } catch (error) {
        // If decryption fails, we'll show the scrambled data
        document.getElementById('decryptedMessage').value = "Decryption failed: " + error.message;
    }
}

function pasteKeys() {
    document.getElementById('privateKeyInput').value = document.getElementById('privateKey').value
}

document.addEventListener('DOMContentLoaded', (event) => {
    const tabLinks = document.querySelectorAll('.nav-link');

    tabLinks.forEach(tab => {
        tab.addEventListener('click', () => {
            localStorage.setItem('activeTab', tab.id);
        });
    });

    // Retrieve the active tab ID from local storage
    const activeTabId = localStorage.getItem('activeTab');

    if (activeTabId) {
        // Remove the 'active' class from all tabs
        tabLinks.forEach(tab => tab.classList.remove('active'));

        // Add the 'active' class to the saved tab
        const activeTab = document.getElementById(activeTabId);
        activeTab.classList.add('active');

        // Show the corresponding tab content
        const tabContentId = activeTab.getAttribute('data-bs-target');
        const tabContent = document.querySelector(tabContentId);
        const allTabContents = document.querySelectorAll('.tab-pane');

        allTabContents.forEach(content => content.classList.remove('show', 'active'));
        tabContent.classList.add('show', 'active');
    }
});
