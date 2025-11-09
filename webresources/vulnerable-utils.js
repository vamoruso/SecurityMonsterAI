//  VULNERABILITÀ #5: Reflected XSS
    function displayGreeting() {
        const userName = document.getElementById('userName').value;
        // VULNERABILE: Inserisce direttamente HTML senza sanitizzazione
        document.getElementById('greeting').innerHTML = 
            '<h3>Ciao ' + userName + '! 👋</h3>';
    }

    //  VULNERABILITÀ #6: DOM-Based XSS
    function performSearch() {
        const query = document.getElementById('searchQuery').value;
        // VULNERABILE: location.hash può essere manipolato
        window.location.hash = query;
        const searchTerm = window.location.hash.substring(1);
        
        // VULNERABILE: innerHTML con input utente
        document.getElementById('searchResults').innerHTML = 
            '<p>Risultati per: <strong>' + decodeURIComponent(searchTerm) + '</strong></p>' +
            '<p>Nessun risultato trovato.</p>';
    }

    //  VULNERABILITÀ #7: SQL Injection (simulato client-side)
    function handleLogin(event) {
        event.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        // VULNERABILE: Costruzione query SQL con concatenazione
        // In un'app reale, questo sarebbe server-side
        const sqlQuery = "SELECT * FROM users WHERE username='" + username + 
                        "' AND password='" + password + "'";
        
        document.getElementById('loginResult').innerHTML = 
            '<div style="background: #fff3cd; padding: 10px; border-radius: 5px;">' +
            '<strong>Query SQL generata:</strong><br>' +
            '<code style="color: #dc3545;">' + sqlQuery + '</code><br><br>' +
            '<strong>⚠️ VULNERABILE A SQL INJECTION!</strong><br>' +
            'Un attaccante può usare: <code>admin\' OR \'1\'=\'1</code>' +
            '</div>';
        
        // Simula bypass autenticazione
        if (username.includes("' OR '") || username.includes("1=1")) {
            document.getElementById('loginResult').innerHTML += 
                '<div style="background: #d4edda; padding: 10px; margin-top: 10px; border-radius: 5px;">' +
                '✅ <strong>Login riuscito!</strong> (Bypassata autenticazione con SQL Injection)' +
                '</div>';
        }
        
        return false;
    }

    //  VULNERABILITÀ #8: Hardcoded Credentials
    function accessAdminPanel() {
        // VULNERABILE: Credenziali hardcoded nel JavaScript
        const ADMIN_USERNAME = "admin";
        const ADMIN_PASSWORD = "SuperAdmin2024!";
        const API_KEY = "sk_live_51HxYzKJxYzKJxYzKJ";
        const DB_CONNECTION = "mysql://root:password123@localhost:3306/banking";
        
        document.getElementById('adminResult').innerHTML = 
            '<div style="background: #f8d7da; padding: 15px; border-radius: 5px;">' +
            ' <strong>CREDENZIALI HARDCODED RILEVATE!</strong><br><br>' +
            '<strong>Admin Username:</strong> ' + ADMIN_USERNAME + '<br>' +
            '<strong>Admin Password:</strong> ' + ADMIN_PASSWORD + '<br>' +
            '<strong>API Key:</strong> ' + API_KEY + '<br>' +
            '<strong>DB Connection:</strong> ' + DB_CONNECTION + '<br><br>' +
            '⚠️ Queste credenziali sono visibili nel codice sorgente!' +
            '</div>';
    }

    //  VULNERABILITÀ #9: Sensitive Data Exposure
    function showAccountDetails() {
        // VULNERABILE: Dati sensibili in chiaro
        const accountData = {
            accountNumber: "IT60X0542811101000000123456",
            creditCard: "4532-1234-5678-9012",
            cvv: "123",
            ssn: "RSSMRA80A01H501U",
            balance: "€ 15,420.50",
            pin: "1234"
        };
        
        document.getElementById('accountDetails').innerHTML = 
            '<div style="background: #fff3cd; padding: 15px; border-radius: 5px;">' +
            '⚠️ <strong>DATI SENSIBILI ESPOSTI!</strong><br><br>' +
            '<strong>IBAN:</strong> ' + accountData.accountNumber + '<br>' +
            '<strong>Carta di Credito:</strong> ' + accountData.creditCard + '<br>' +
            '<strong>CVV:</strong> ' + accountData.cvv + '<br>' +
            '<strong>Codice Fiscale:</strong> ' + accountData.ssn + '<br>' +
            '<strong>PIN:</strong> ' + accountData.pin + '<br>' +
            '<strong>Saldo:</strong> ' + accountData.balance + '<br><br>' +
            ' Questi dati non dovrebbero MAI essere esposti lato client!' +
            '</div>';
    }

    //  VULNERABILITÀ #10: Insecure Direct Object Reference (IDOR)
    function loadDocument() {
        const docId = document.getElementById('docId').value;
        
        // VULNERABILE: Nessun controllo di autorizzazione
        // Un attaccante può cambiare l'ID per accedere documenti altrui
        const documents = {
            1: "Estratto conto Mario Rossi - Gennaio 2025",
            2: "Contratto prestito Luigi Bianchi - Confidenziale",
            3: "Dati personali Anna Verdi - PRIVATO",
            4: "Transazioni admin - SOLO INTERNO",
            5: "Backup database - RISERVATO"
        };
        
        document.getElementById('documentContent').innerHTML = 
            '<div style="background: #f8d7da; padding: 15px; border-radius: 5px;">' +
            ' <strong>IDOR VULNERABILITY!</strong><br><br>' +
            '<strong>Documento #' + docId + ':</strong><br>' +
            (documents[docId] || 'Documento non trovato') + '<br><br>' +
            '⚠️ Nessun controllo di autorizzazione!<br>' +
            'Un attaccante può accedere a QUALSIASI documento cambiando l\'ID!' +
            '</div>';
    }

    //  VULNERABILITÀ #12: Insecure Random
    function generateToken() {
        // VULNERABILE: Math.random() non è crittograficamente sicuro
        return Math.random().toString(36).substring(2, 15);
    }

    //  VULNERABILITÀ #13: Local Storage con dati sensibili
    function saveCredentials() {
        // VULNERABILE: Dati sensibili in localStorage
        localStorage.setItem('username', 'admin');
        localStorage.setItem('password', 'Admin123!');
        localStorage.setItem('sessionToken', generateToken());
        localStorage.setItem('creditCard', '4532-1234-5678-9012');
    }

    //  VULNERABILITÀ #15: Eval con input utente (estremo)
    function calculateExpression() {
        const expr = prompt('Inserisci espressione matematica:');
        if (expr) {
            // ESTREMAMENTE VULNERABILE: eval con input utente
            try {
                const result = eval(expr);
                alert('Risultato: ' + result);
            } catch (e) {
                alert('Errore: ' + e.message);
            }
        }
    }



/**
 *  VULNERABLE UTILITIES
 * File JavaScript con multiple vulnerabilità per testing
 * ATTENZIONE: NON USARE IN PRODUZIONE!
 */

//  VULNERABILITÀ #1: Hardcoded API Keys
const CONFIG = {
    apiKey: 'AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    secretKey: 'sk_live_51HxYzKJxYzKJxYzKJxYzKJxYzKJ',
    awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
    awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    stripeKey: 'sk_live_51HxYzKJxYzKJxYzKJxYzKJ',
    jwtSecret: 'my-super-secret-jwt-key-12345',
    dbPassword: 'MySQLPass2024!'
};

//  VULNERABILITÀ #2: Insecure Cookie Handling
function setCookie(name, value) {
    // VULNERABILE: Cookie senza flags sicuri
    document.cookie = name + "=" + value + "; path=/";
    // Manca: Secure; HttpOnly; SameSite
}

//  VULNERABILITÀ #3: XSS in cookie reading
function getCookie(name) {
    const value = "; " + document.cookie;
    const parts = value.split("; " + name + "=");
    if (parts.length === 2) {
        // VULNERABILE: Nessuna sanitizzazione
        return parts.pop().split(";").shift();
    }
}

//  VULNERABILITÀ #4: Insecure AJAX without CSRF
function makeApiCall(endpoint, data) {
    // VULNERABILE: Nessun CSRF token
    fetch(CONFIG.apiEndpoint + endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': CONFIG.apiKey  //  API key esposta
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        //  VULNERABILITÀ #5: eval con response
        eval('var result = ' + JSON.stringify(data));
        console.log(result);
    });
}

//  VULNERABILITÀ #6: Insecure redirect
function redirectTo(url) {
    // VULNERABILE: Open redirect
    window.location = url;
    // Nessuna validazione dell'URL
}

//  VULNERABILITÀ #7: Client-side authentication
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

//  VULNERABILITÀ #8: Weak encryption
function encryptData(data) {
    // VULNERABILE: ROT13 non è crittografia!
    return data.replace(/[a-zA-Z]/g, function(c) {
        return String.fromCharCode(
            (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
        );
    });
}

//  VULNERABILITÀ #9: SQL Query builder (client-side)
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

//  VULNERABILITÀ #10: Insecure random
function generateSessionId() {
    // VULNERABILE: Math.random() predicibile
    return 'sess_' + Math.random().toString(36).substring(2, 15);
}

//  VULNERABILITÀ #11: Command injection (simulato)
function executeCommand(cmd) {
    // In un context Node.js sarebbe:
    // require('child_process').exec(cmd);
    console.log('Executing: ' + cmd);
    // VULNERABILE: Nessuna validazione comando
}

//  VULNERABILITÀ #12: Path traversal
function loadFile(filename) {
    // VULNERABILE: Path traversal
    fetch('/api/file?path=' + filename)
        .then(r => r.text())
        .then(content => {
            document.getElementById('fileContent').innerHTML = content;
        });
    // Exploit: filename = '../../../etc/passwd'
}

//  VULNERABILITÀ #13: Prototype pollution
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

//  VULNERABILITÀ #14: Insecure deserialization
function deserialize(serialized) {
    // VULNERABILE: eval per deserializzazione
    return eval('(' + serialized + ')');
}

//  VULNERABILITÀ #15: CORS misconfiguration (headers)
function setupCORS() {
    // In un server questo sarebbe pericoloso:
    // res.setHeader('Access-Control-Allow-Origin', '*');
    // res.setHeader('Access-Control-Allow-Credentials', 'true');
    console.log('CORS: Allow all origins with credentials - INSECURE!');
}

//  VULNERABILITÀ #16: Sensitive data in URL
function trackUser(userId, email, creditCard) {
    // VULNERABILE: Dati sensibili in URL (analytics)
    const trackingUrl = 'https://analytics.example.com/track?user=' + userId + 
                       '&email=' + email + 
                       '&cc=' + creditCard;
    
    // Viene salvato nei log del server, browser history, ecc.
    fetch(trackingUrl);
}

//  VULNERABILITÀ #17: Race condition
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

//  VULNERABILITÀ #18: Information disclosure
function getErrorDetails(error) {
    // VULNERABILE: Stack trace esposti
    return {
        message: error.message,
        stack: error.stack,
        config: CONFIG,  //  Espone configurazione
        environment: {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            cookies: document.cookie,
            localStorage: localStorage
        }
    };
}

//  VULNERABILITÀ #19: Timing attack
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

//  VULNERABILITÀ #20: Clickjacking vulnerability
function allowFraming() {
    // Manca: X-Frame-Options header
    // Manca: Content-Security-Policy frame-ancestors
    console.log('Page can be framed - Clickjacking possible!');
}

// Auto-init
(function() {
    console.log('🔓 Vulnerable utilities loaded');
    console.log(' CONFIG:', CONFIG);
    
    //  Espone funzioni globalmente
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