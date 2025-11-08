/**
 * 🔴 VULNERABLE UTILITIES
 * File JavaScript con multiple vulnerabilità per testing
 * ATTENZIONE: NON USARE IN PRODUZIONE!
 */

// 🔴 VULNERABILITÀ #1: Hardcoded API Keys
const CONFIG = {
    apiKey: 'AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    secretKey: 'sk_live_51HxYzKJxYzKJxYzKJxYzKJxYzKJ',
    awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
    awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    stripeKey: 'sk_live_51HxYzKJxYzKJxYzKJxYzKJ',
    jwtSecret: 'my-super-secret-jwt-key-12345',
    dbPassword: 'MySQLPass2024!'
};

// 🔴 VULNERABILITÀ #2: Insecure Cookie Handling
function setCookie(name, value) {
    // VULNERABILE: Cookie senza flags sicuri
    document.cookie = name + "=" + value + "; path=/";
    // Manca: Secure; HttpOnly; SameSite
}

// 🔴 VULNERABILITÀ #3: XSS in cookie reading
function getCookie(name) {
    const value = "; " + document.cookie;
    const parts = value.split("; " + name + "=");
    if (parts.length === 2) {
        // VULNERABILE: Nessuna sanitizzazione
        return parts.pop().split(";").shift();
    }
}

// 🔴 VULNERABILITÀ #4: Insecure AJAX without CSRF
function makeApiCall(endpoint, data) {
    // VULNERABILE: Nessun CSRF token
    fetch(CONFIG.apiEndpoint + endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': CONFIG.apiKey  // 🔴 API key esposta
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        // 🔴 VULNERABILITÀ #5: eval con response
        eval('var result = ' + JSON.stringify(data));
        console.log(result);
    });
}

// 🔴 VULNERABILITÀ #6: Insecure redirect
function redirectTo(url) {
    // VULNERABILE: Open redirect
    window.location = url;
    // Nessuna validazione dell'URL
}

// 🔴 VULNERABILITÀ #7: Client-side authentication
function authenticate(username, password) {
    // VULNERABILE: Autenticazione lato client
    const validUsers = {
        'admin': 'admin123',
        'user': 'password',
        'test': 'test123'
    };
    
    if (validUsers[username] === password) {
        setCookie('authenticated', 'true');
        setCookie('role', username === 'admin' ? 'admin' : 'user');
        return true;
    }
    return false;
}

// 🔴 VULNERABILITÀ #8: Weak encryption
function encryptData(data) {
    // VULNERABILE: ROT13 non è crittografia!
    return data.replace(/[a-zA-Z]/g, function(c) {
        return String.fromCharCode(
            (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
        );
    });
}

// 🔴 VULNERABILITÀ #9: SQL Query builder (client-side)
function buildQuery(table, conditions) {
    // VULNERABILE: SQL Injection
    let query = "SELECT * FROM " + table + " WHERE ";
    const clauses = [];
    
    for (let key in conditions) {
        clauses.push(key + "='" + conditions[key] + "'");
    }
    
    query += clauses.join(" AND ");
    return query;
}

// 🔴 VULNERABILITÀ #10: Insecure random
function generateSessionId() {
    // VULNERABILE: Math.random() predicibile
    return 'sess_' + Math.random().toString(36).substring(2, 15);
}

// 🔴 VULNERABILITÀ #11: Command injection (simulato)
function executeCommand(cmd) {
    // In un context Node.js sarebbe:
    // require('child_process').exec(cmd);
    console.log('Executing: ' + cmd);
    // VULNERABILE: Nessuna validazione comando
}

// 🔴 VULNERABILITÀ #12: Path traversal
function loadFile(filename) {
    // VULNERABILE: Path traversal
    fetch('/api/file?path=' + filename)
        .then(r => r.text())
        .then(content => {
            document.getElementById('fileContent').innerHTML = content;
        });
    // Exploit: filename = '../../../etc/passwd'
}

// 🔴 VULNERABILITÀ #13: Prototype pollution
function merge(target, source) {
    // VULNERABILE: Prototype pollution
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 🔴 VULNERABILITÀ #14: Insecure deserialization
function deserialize(serialized) {
    // VULNERABILE: eval per deserializzazione
    return eval('(' + serialized + ')');
}

// 🔴 VULNERABILITÀ #15: CORS misconfiguration (headers)
function setupCORS() {
    // In un server questo sarebbe pericoloso:
    // res.setHeader('Access-Control-Allow-Origin', '*');
    // res.setHeader('Access-Control-Allow-Credentials', 'true');
    console.log('CORS: Allow all origins with credentials - INSECURE!');
}

// 🔴 VULNERABILITÀ #16: Sensitive data in URL
function trackUser(userId, email, creditCard) {
    // VULNERABILE: Dati sensibili in URL (analytics)
    const trackingUrl = 'https://analytics.example.com/track?user=' + userId + 
                       '&email=' + email + 
                       '&cc=' + creditCard;
    
    // Viene salvato nei log del server, browser history, ecc.
    fetch(trackingUrl);
}

// 🔴 VULNERABILITÀ #17: Race condition
let balance = 1000;

function withdraw(amount) {
    // VULNERABILE: Race condition
    if (balance >= amount) {
        // Un altro thread potrebbe eseguire qui
        setTimeout(() => {
            balance -= amount;
            console.log('Withdrawn: ' + amount + ', Balance: ' + balance);
        }, 100);
        return true;
    }
    return false;
}

// 🔴 VULNERABILITÀ #18: Information disclosure
function getErrorDetails(error) {
    // VULNERABILE: Stack trace esposti
    return {
        message: error.message,
        stack: error.stack,
        config: CONFIG,  // 🔴 Espone configurazione
        environment: {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            cookies: document.cookie,
            localStorage: localStorage
        }
    };
}

// 🔴 VULNERABILITÀ #19: Timing attack
function comparePassword(input, stored) {
    // VULNERABILE: Timing attack
    if (input.length !== stored.length) {
        return false;
    }
    
    for (let i = 0; i < input.length; i++) {
        if (input[i] !== stored[i]) {
            return false;  // Ritorna appena trova differenza
        }
    }
    return true;
}

// 🔴 VULNERABILITÀ #20: Clickjacking vulnerability
function allowFraming() {
    // Manca: X-Frame-Options header
    // Manca: Content-Security-Policy frame-ancestors
    console.log('Page can be framed - Clickjacking possible!');
}

// Auto-init
(function() {
    console.log('🔓 Vulnerable utilities loaded');
    console.log('🔴 CONFIG:', CONFIG);
    
    // 🔴 Espone funzioni globalmente
    window.vulnerableUtils = {
        setCookie,
        getCookie,
        authenticate,
        encryptData,
        buildQuery,
        generateSessionId,
        loadFile,
        deserialize,
        trackUser,
        comparePassword
    };
})();