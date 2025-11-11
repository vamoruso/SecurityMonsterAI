//  VULNERABILITA #5: Reflected XSS
    function displayGreeting() {
        const userName = document.getElementById('userName').value;
        // VULNERABILE: Inserisce direttamente HTML senza sanitizzazione
        document.getElementById('greeting').innerHTML = 
            '<h3>Ciao ' + userName + '! 👋</h3>';
    }

    //  VULNERABILITA #6: DOM-Based XSS
    function performSearch() {
        const query = document.getElementById('searchQuery').value;
        // VULNERABILE: location.hash puo essere manipolato
        window.location.hash = query;
        const searchTerm = window.location.hash.substring(1);
        
        // VULNERABILITA: innerHTML con input utente
        document.getElementById('searchResults').innerHTML = 
            '<p>Risultati per: <strong>' + decodeURIComponent(searchTerm) + '</strong></p>' +
            '<p>Nessun risultato trovato.</p>';
    }

    //  VULNERABILITA #7: SQL Injection (simulato client-side)
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
            'Un attaccante puo usare: <code>admin\' OR \'1\'=\'1</code>' +
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

    //  VULNERABILITA #8: Hardcoded Credentials
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

    //  VULNERABILITA #9: Sensitive Data Exposure
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

    //  VULNERABILITA #10: Insecure Direct Object Reference (IDOR)
    function loadDocument() {
        const docId = document.getElementById('docId').value;
        
        // VULNERABILE: Nessun controllo di autorizzazione
        // Un attaccante puo cambiare l'ID per accedere documenti altrui
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
            'Un attaccante puo accedere a QUALSIASI documento cambiando l\'ID!' +
            '</div>';
    }

    //  VULNERABILITA #12: Insecure Random
    function generateToken() {
        // VULNERABILE: Math.random() non è crittograficamente sicuro
        return Math.random().toString(36).substring(2, 15);
    }

    //  VULNERABILITA #13: Local Storage con dati sensibili
    function saveCredentials() {
        // VULNERABILE: Dati sensibili in localStorage
        localStorage.setItem('username', 'admin');
        localStorage.setItem('password', 'Admin123!');
        localStorage.setItem('sessionToken', generateToken());
        localStorage.setItem('creditCard', '4532-1234-5678-9012');
    }

    //  VULNERABILITA #15: Eval con input utente (estremo)
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


